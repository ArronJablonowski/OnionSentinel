#!/usr/bin/env python3
"""Persistent LAN report portal for Arron's local HTML reports/projects."""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import heapq
import hashlib
import hmac
import html
import importlib.util
import ipaddress
import json
import math
import mimetypes
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
from dataclasses import dataclass
from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

PORTAL_SOURCE_DIR = Path(__file__).resolve().parent
if str(PORTAL_SOURCE_DIR) not in sys.path:
    sys.path.insert(0, str(PORTAL_SOURCE_DIR))

import soc_alert_api
import software_inventory
import cti_program
from artifact_cache import ArtifactCache
from http_runtime import BoundedResponseError, read_bounded_json
from jsonl_log import JsonlLogIndex
from portal_catalog_routes import classify_catalog_route
from portal_ai_settings_normalizer import (
    SocAiSettingsNormalizationPolicy,
    normalize_soc_ai_settings as normalize_ai_settings,
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
from portal_admin_dashboard import (
    AdminDashboardSources,
    compose_admin_dashboard,
    render_admin_dashboard as render_admin_dashboard_view,
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
    compose_group_query_payload,
    fallback_query_plan,
    parse_group_query_request,
    summary_query_plan,
)
from portal_incident_actions import (
    IncidentStatusPayloadError,
    normalize_incident_status_payload,
)
from portal_incident_read_model import (
    IncidentRowCallbacks,
    IncidentQueryError,
    empty_incident_page,
    parse_incident_list_request,
)
from portal_incident_list_service import compose_incident_list_rows
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
    IncidentCaseNotFound,
    IncidentSchemaUnavailable,
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
from portal_soc_write_dispatch import (
    SocWriteCallbacks,
    dispatch_authorized_soc_write,
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
class Report:
    rid: str
    title: str
    path: Path
    rel: str
    category: str
    size: int
    mtime: float
    is_index: bool


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
    existing = sys.modules.get("_onion_sentinel_asset_inventory")
    if existing is not None:
        return existing
    candidates = (
        PORTAL_SOURCE_DIR / "asset_inventory.py",
        PORTAL_SOURCE_DIR.parent / "n8n" / "bin" / "asset_inventory.py",
        HOME / "n8n-local" / "bin" / "asset_inventory.py",
    )
    for candidate in candidates:
        if not candidate.is_file():
            continue
        spec = importlib.util.spec_from_file_location(
            "_onion_sentinel_asset_inventory",
            candidate,
        )
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    raise RuntimeError("asset inventory validator is unavailable")


def load_asset_inventory_data() -> tuple[dict, str]:
    """Return the PostgreSQL export used by investigation identity resolution."""
    if ASSET_DATABASE_READ_ENABLED:
        with ASSET_INVENTORY_CACHE_LOCK:
            if (
                float(ASSET_INVENTORY_CACHE.get("expires_at") or 0) > time.time()
                and isinstance(ASSET_INVENTORY_CACHE.get("inventory"), dict)
            ):
                return dict(ASSET_INVENTORY_CACHE["inventory"]), ""
        try:
            result = alert_store_get_json("/assets/snapshot", timeout=5.0)
            raw_inventory = result.get("inventory")
            inventory = _asset_inventory_module().validate_asset_inventory(
                raw_inventory
            )
            inventory["inventory_status"] = "database"
        except (
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            return {
                "assets": [],
                "inventory_status": "unavailable",
            }, f"PostgreSQL asset inventory unavailable: {exc}"
        with ASSET_INVENTORY_CACHE_LOCK:
            ASSET_INVENTORY_CACHE["signature"] = "postgresql"
            ASSET_INVENTORY_CACHE["inventory"] = inventory
            ASSET_INVENTORY_CACHE["expires_at"] = time.time() + 5.0
        return dict(inventory), ""

    # Offline disaster recovery and unit tests retain a strictly validated
    # file reader. Production never silently falls back from PostgreSQL to this
    # snapshot because that would create two competing sources of truth.
    path = Path(ASSET_INVENTORY_FILE)
    try:
        metadata = path.stat()
        if not path.is_file() or metadata.st_size > ASSET_INVENTORY_MAX_BYTES:
            raise ValueError("asset inventory is not a bounded regular file")
        signature: object = (
            str(path.resolve()),
            metadata.st_mtime_ns,
            metadata.st_size,
        )
    except FileNotFoundError:
        return {
            "schema": "onion-sentinel-asset-inventory-v1",
            "version": 0,
            "generated_at": "",
            "assets": [],
            "inventory_status": "missing",
        }, ""
    except (OSError, ValueError) as exc:
        return {"assets": [], "inventory_status": "invalid"}, str(exc)

    with ASSET_INVENTORY_CACHE_LOCK:
        if (
            ASSET_INVENTORY_CACHE.get("signature") == signature
            and isinstance(ASSET_INVENTORY_CACHE.get("inventory"), dict)
        ):
            return dict(ASSET_INVENTORY_CACHE["inventory"]), ""
        try:
            inventory = _asset_inventory_module().load_asset_inventory(path)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            return {"assets": [], "inventory_status": "invalid"}, str(exc)
        ASSET_INVENTORY_CACHE["signature"] = signature
        ASSET_INVENTORY_CACHE["inventory"] = inventory
        return dict(inventory), ""


def _asset_record_state(
    asset: dict,
    observed_at: dt.datetime,
) -> str:
    try:
        valid_from = parse_iso_timestamp(asset.get("valid_from"))
        valid_until = (
            parse_iso_timestamp(asset.get("valid_until"))
            if asset.get("valid_until")
            else None
        )
    except (TypeError, ValueError):
        return "invalid"
    if valid_from.tzinfo is None:
        return "invalid"
    if observed_at < valid_from:
        return "scheduled"
    if valid_until is not None and observed_at >= valid_until:
        return "expired"
    return "current"


def _asset_public_record(asset: dict, state: str) -> dict:
    """Expose operational identity fields while withholding owner/behavior notes."""
    identifiers = (
        asset.get("identifiers")
        if isinstance(asset.get("identifiers"), dict)
        else {}
    )
    return {
        "asset_id": str(asset.get("asset_id") or ""),
        "state": state,
        "ip_addresses": list(identifiers.get("ip") or []),
        "hostnames": list(identifiers.get("hostname") or []),
        "mac_addresses": list(identifiers.get("mac") or []),
        "role": str(asset.get("role") or ""),
        "platform": str(asset.get("platform") or ""),
        "criticality": str(asset.get("criticality") or "unknown"),
        "confidence": str(asset.get("confidence") or "unknown"),
        "valid_from": str(asset.get("valid_from") or ""),
        "valid_until": str(asset.get("valid_until") or ""),
        "source_type": str(asset.get("source_type") or ""),
        "source_ref": str(asset.get("source_ref") or ""),
    }


def load_dhcp_asset_discovery_state_data() -> tuple[dict, str]:
    """Load the bounded collector state without treating absence as an error."""
    if ASSET_DATABASE_READ_ENABLED:
        try:
            result = alert_store_get_json("/assets/dhcp-state", timeout=5.0)
            state = result.get("state")
            if (
                not isinstance(state, dict)
                or state.get("schema")
                != "onion-sentinel-dhcp-asset-observations-v1"
                or not isinstance(state.get("collection"), dict)
                or not isinstance(state.get("observations"), list)
                or len(state["observations"]) > 100_000
            ):
                raise ValueError("database DHCP state failed validation")
            return state, ""
        except (RuntimeError, TypeError, ValueError) as exc:
            return {
                "collection": {"status": "unavailable"},
                "observations": [],
            }, f"PostgreSQL DHCP state unavailable: {exc}"

    state_path = Path(DHCP_ASSET_DISCOVERY_STATE_FILE)
    try:
        metadata = state_path.stat()
        if (
            not state_path.is_file()
            or metadata.st_size > DHCP_ASSET_DISCOVERY_MAX_BYTES
        ):
            raise ValueError(
                "DHCP observation state is not a bounded regular file"
            )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if (
            not isinstance(state, dict)
            or state.get("schema")
            != "onion-sentinel-dhcp-asset-observations-v1"
            or not isinstance(state.get("collection"), dict)
            or not isinstance(state.get("observations"), list)
            or len(state["observations"]) > 5000
        ):
            raise ValueError("DHCP observation state failed schema validation")
        return state, ""
    except FileNotFoundError:
        return {
            "updated_at": "",
            "collection": {
                "status": "never_run",
                "last_attempt_at": "",
                "last_success_at": "",
                "last_error": "",
            },
            "observations": [],
        }, ""
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "collection": {"status": "invalid"},
            "observations": [],
        }, str(exc)


def _mac_address_scope(value: object) -> str:
    """Classify a normalized MAC without claiming a vendor identity."""
    text = str(value or "").strip().lower()
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", text):
        return "unknown"
    first_octet = int(text[:2], 16)
    if first_octet & 1:
        return "multicast"
    if first_octet & 2:
        return "locally_administered"
    return "globally_administered"


def _annotate_exact_ip_dhcp_macs(
    records: list[dict],
    observed_at: dt.datetime,
) -> dict:
    """Attach display-only DHCP MAC evidence to exact-IP asset matches.

    These fields deliberately remain separate from ``mac_addresses``. The
    latter is authoritative inventory, while the former is passive evidence
    that still requires operator review.
    """
    state, state_error = load_dhcp_asset_discovery_state_data()
    collection = (
        state.get("collection")
        if isinstance(state.get("collection"), dict)
        else {}
    )
    status = {
        "status": str(collection.get("status") or "unknown")[:32],
        "updated_at": str(state.get("updated_at") or "")[:64],
        "error": str(
            state_error or collection.get("last_error") or ""
        )[:300],
    }
    if state_error:
        return status

    by_ip: dict[str, list[dict]] = {}
    for raw in state.get("observations", []):
        if not isinstance(raw, dict):
            continue
        mac = str(raw.get("mac_address") or "").strip().lower()
        scope = _mac_address_scope(mac)
        if scope in {"unknown", "multicast"}:
            continue
        try:
            address = str(
                ipaddress.ip_address(str(raw.get("current_ip") or "").strip())
            )
            last_seen = parse_iso_timestamp(raw.get("last_seen"))
            if last_seen.tzinfo is None:
                raise ValueError("last_seen lacks offset")
            last_seen = last_seen.astimezone(dt.timezone.utc)
        except (TypeError, ValueError):
            continue
        lease_expires = None
        if raw.get("lease_expires_at"):
            try:
                lease_expires = parse_iso_timestamp(
                    raw["lease_expires_at"]
                ).astimezone(dt.timezone.utc)
            except (TypeError, ValueError):
                lease_expires = None
        stale = (
            last_seen < observed_at - dt.timedelta(hours=24)
            and (lease_expires is None or lease_expires < observed_at)
        )
        by_ip.setdefault(address, []).append(
            {
                "mac": mac,
                "scope": scope,
                "last_seen": str(raw.get("last_seen") or "")[:64],
                "last_seen_value": last_seen,
                "stale": stale,
            }
        )

    for record in records:
        if not isinstance(record, dict):
            continue
        candidates: list[dict] = []
        for raw_address in record.get("ip_addresses") or []:
            try:
                address = str(ipaddress.ip_address(str(raw_address).strip()))
            except ValueError:
                continue
            candidates.extend(by_ip.get(address, []))
        if not candidates:
            continue

        fresh = [item for item in candidates if not item["stale"]]
        selected = fresh or candidates
        by_mac: dict[str, dict] = {}
        for item in sorted(
            selected,
            key=lambda entry: entry["last_seen_value"],
            reverse=True,
        ):
            by_mac.setdefault(str(item["mac"]), item)
        if len(by_mac) != 1:
            record["observed_mac_ambiguous"] = True
            record["observed_mac_source"] = "zeek-dhcp-exact-ip"
            continue

        evidence = next(iter(by_mac.values()))
        record["observed_mac_addresses"] = [str(evidence["mac"])]
        record["observed_mac_source"] = "zeek-dhcp-exact-ip"
        record["observed_mac_scope"] = str(evidence["scope"])
        record["observed_mac_last_seen"] = str(evidence["last_seen"])
        record["observed_mac_stale"] = bool(evidence["stale"])
    return status


def _dhcp_asset_inventory_overlay(
    inventory: dict,
    observed_at: dt.datetime,
) -> tuple[dict[str, dict], list[dict], dict]:
    """Build a display-only DHCP overlay without changing authoritative facts."""
    state, state_error = load_dhcp_asset_discovery_state_data()
    collection = (
        state.get("collection")
        if isinstance(state.get("collection"), dict)
        else {}
    )
    status = {
        "status": str(collection.get("status") or "unknown")[:32],
        "updated_at": str(state.get("updated_at") or "")[:64],
        "error": str(
            state_error or collection.get("last_error") or ""
        )[:300],
    }
    if state_error:
        return {}, [], status

    current_assets: dict[str, dict] = {}
    indexes: dict[str, dict[str, set[str]]] = {
        "ip": {},
        "hostname": {},
        "mac": {},
    }
    for raw in inventory.get("assets", []):
        if (
            not isinstance(raw, dict)
            or _asset_record_state(raw, observed_at) != "current"
        ):
            continue
        asset_id = str(raw.get("asset_id") or "")
        if not asset_id:
            continue
        public = _asset_public_record(raw, "current")
        current_assets[asset_id] = public
        identifiers = (
            raw.get("identifiers")
            if isinstance(raw.get("identifiers"), dict)
            else {}
        )
        for kind in indexes:
            for raw_value in identifiers.get(kind) or []:
                value = str(raw_value or "").strip().rstrip(".").lower()
                if value:
                    indexes[kind].setdefault(value, set()).add(asset_id)

    overlays: dict[str, dict] = {}
    discovered: dict[str, dict] = {}
    raw_observations = (
        state.get("observations")
        if isinstance(state.get("observations"), list)
        else []
    )
    for raw in sorted(
        (item for item in raw_observations if isinstance(item, dict)),
        key=lambda item: (
            str(item.get("last_seen") or ""),
            str(item.get("discovery_id") or ""),
        ),
    ):
        try:
            current_ip = str(
                ipaddress.ip_address(str(raw.get("current_ip") or "").strip())
            )
            last_seen = parse_iso_timestamp(raw.get("last_seen"))
            if last_seen.tzinfo is None:
                raise ValueError("last_seen lacks offset")
            last_seen = last_seen.astimezone(dt.timezone.utc)
        except (TypeError, ValueError):
            continue
        lease_expires = None
        if raw.get("lease_expires_at"):
            try:
                lease_expires = parse_iso_timestamp(
                    raw["lease_expires_at"]
                ).astimezone(dt.timezone.utc)
            except (TypeError, ValueError):
                lease_expires = None
        stale = (
            last_seen < observed_at - dt.timedelta(hours=24)
            and (lease_expires is None or lease_expires < observed_at)
        )
        if stale:
            continue

        hostname = (
            str(raw.get("hostname") or "").strip().rstrip(".").lower()
        )
        mac = str(raw.get("mac_address") or "").strip().lower()
        stable_matches: set[str] = set()
        if hostname:
            stable_matches.update(indexes["hostname"].get(hostname, set()))
        if mac:
            stable_matches.update(indexes["mac"].get(mac, set()))
        ip_matches = indexes["ip"].get(current_ip, set())

        if (
            len(stable_matches) == 1
            and not (ip_matches - stable_matches)
        ):
            asset_id = next(iter(stable_matches))
            authoritative = current_assets[asset_id]
            overlays[asset_id] = {
                "configured_ip_addresses": list(
                    authoritative.get("ip_addresses") or []
                ),
                "ip_addresses": [current_ip],
                "current_ip_source": "zeek-dhcp",
                "dhcp_last_seen": str(raw.get("last_seen") or "")[:64],
                "dhcp_lease_expires_at": str(
                    raw.get("lease_expires_at") or ""
                )[:64],
            }
            continue

        if stable_matches or ip_matches:
            # Conflicting or IP-only claims remain in the review table and
            # cannot change the primary inventory presentation.
            continue

        discovery_id = str(raw.get("discovery_id") or "")[:64]
        if not discovery_id:
            continue
        asset_id = f"dhcp-{discovery_id}"
        discovered[asset_id] = {
            "asset_id": asset_id,
            "state": "observed",
            "ip_addresses": [current_ip],
            "configured_ip_addresses": [],
            "hostnames": [hostname] if hostname else [],
            "mac_addresses": [mac] if mac else [],
            "mac_address_scope": _mac_address_scope(mac),
            "role": "DHCP-discovered LAN client",
            "platform": "",
            "criticality": "unknown",
            "confidence": "low",
            "valid_from": str(raw.get("first_seen") or "")[:64],
            "valid_until": str(raw.get("lease_expires_at") or "")[:64],
            "source_type": "zeek-dhcp-observation",
            "source_ref": (
                "Passive DHCP evidence; operator verification required"
            ),
            "current_ip_source": "zeek-dhcp",
            "dhcp_last_seen": str(raw.get("last_seen") or "")[:64],
            "dhcp_lease_expires_at": str(
                raw.get("lease_expires_at") or ""
            )[:64],
        }
    return overlays, list(discovered.values()), status


def asset_inventory_response(
    *,
    observed_at: dt.datetime | None = None,
    query: dict[str, list[str]] | None = None,
) -> tuple[int, dict]:
    """Return current authoritative asset-to-address assignments."""
    if ASSET_DATABASE_READ_ENABLED and observed_at is None:
        query = query or {}
        allowed = {
            "limit": (query.get("limit") or ["100"])[0],
            "offset": (query.get("offset") or ["0"])[0],
            "search": (query.get("search") or [""])[0],
            "sort": (query.get("sort") or ["asset_id"])[0],
            "direction": (query.get("direction") or ["asc"])[0],
            "state": (query.get("state") or ["current"])[0],
        }
        encoded = urlencode(allowed)
        try:
            payload = alert_store_get_json(
                f"/assets/inventory?{encoded}",
                timeout=5.0,
            )
        except RuntimeError as exc:
            return HTTPStatus.SERVICE_UNAVAILABLE, {
                "ok": False,
                "inventory_status": "unavailable",
                "storage_backend": "postgresql",
                "error": f"Asset inventory unavailable: {exc}",
                "assets": [],
            }
        now = dt.datetime.now(dt.timezone.utc)
        records = payload.get("assets")
        discovery_status = (
            _annotate_exact_ip_dhcp_macs(records, now)
            if isinstance(records, list)
            else {"status": "unavailable"}
        )
        payload["dhcp_discovery"] = discovery_status
        payload.setdefault("discovered_asset_count", 0)
        return HTTPStatus.OK, payload

    now = observed_at or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        now = now.astimezone()
    now = now.astimezone(dt.timezone.utc)
    inventory, error = load_asset_inventory_data()
    records = []
    state_counts = {"current": 0, "scheduled": 0, "expired": 0, "invalid": 0}
    for raw in inventory.get("assets", []):
        if not isinstance(raw, dict):
            continue
        state = _asset_record_state(raw, now)
        state_counts[state] = state_counts.get(state, 0) + 1
        if state == "current":
            records.append(_asset_public_record(raw, state))
    overlays, discovered, discovery_status = _dhcp_asset_inventory_overlay(
        inventory,
        now,
    )
    for record in records:
        overlay = overlays.get(str(record.get("asset_id") or ""))
        if overlay:
            record.update(overlay)
    records.extend(discovered)
    state_counts["observed"] = len(discovered)
    records.sort(
        key=lambda item: (
            str(item.get("asset_id") or "").lower(),
            str(item.get("valid_from") or ""),
        )
    )
    status = str(inventory.get("inventory_status") or "loaded")
    payload = {
        "ok": not error,
        "inventory_status": status,
        "dhcp_discovery": discovery_status,
        "generated_at": str(inventory.get("generated_at") or ""),
        "observed_at": format_iso_timestamp(now, utc_z=True),
        "records_total": sum(state_counts.values()),
        "authoritative_asset_count": len(records) - len(discovered),
        "discovered_asset_count": len(discovered),
        "current_asset_count": len(records),
        "current_ip_count": sum(len(item["ip_addresses"]) for item in records),
        "current_hostname_count": sum(len(item["hostnames"]) for item in records),
        "state_counts": state_counts,
        "assets": records,
    }
    if error:
        payload["error"] = f"Asset inventory unavailable: {error}"
        return HTTPStatus.SERVICE_UNAVAILABLE, payload
    return HTTPStatus.OK, payload


def software_inventory_response(
    *,
    observed_at: dt.datetime | None = None,
    query: dict[str, list[str]] | None = None,
) -> tuple[int, dict]:
    """Return only the bounded, collector-produced Software Inventory view."""
    # Restricted-node responses keep endpoint hostnames pseudonymous. Resolve
    # those stable references only against one complete, already-public
    # authoritative Asset Inventory. Supplying that identity view while the
    # software snapshot is built lets trusted endpoint OS evidence correlate
    # before filtering and pagination. Ambiguous identifiers remain unlabeled.
    assets: list[dict] = []
    asset_inventory_complete = False
    offset = 0
    for _page_number in range(software_inventory.ASSET_LABEL_MAX_PAGES):
        inventory_status, inventory = asset_inventory_response(
            query={
                "limit": [str(software_inventory.ASSET_LABEL_PAGE_SIZE)],
                "offset": [str(offset)],
                "search": [""],
                "sort": ["asset_id"],
                "direction": ["asc"],
                "state": ["current"],
            }
        )
        if inventory_status != HTTPStatus.OK or not isinstance(inventory, dict):
            break
        page_assets = inventory.get("assets")
        if not isinstance(page_assets, list):
            break
        if len(page_assets) > software_inventory.ASSET_LABEL_PAGE_SIZE:
            break
        remaining = software_inventory.ASSET_LABEL_MAX_RECORDS - len(assets)
        if len(page_assets) > remaining:
            break
        assets.extend(item for item in page_assets if isinstance(item, dict))
        page = inventory.get("page")
        if not isinstance(page, dict) or page.get("has_more") is not True:
            asset_inventory_complete = True
            break
        returned = len(page_assets)
        if returned <= 0:
            break
        next_offset = offset + returned
        if next_offset <= offset:
            break
        offset = next_offset

    if SOFTWARE_DATABASE_READ_ENABLED:
        query = query or {}
        allowed = {
            "limit": (query.get("limit") or ["100"])[0],
            "offset": (query.get("offset") or ["0"])[0],
            "search": (query.get("search") or [""])[0],
            "tier": (query.get("tier") or ["all"])[0],
            "confidence": (query.get("confidence") or ["all"])[0],
            "freshness": (query.get("freshness") or ["all"])[0],
            "platform": (query.get("platform") or ["all"])[0],
            "window": (query.get("window") or ["30d"])[0],
            "sort": (query.get("sort") or ["last_seen"])[0],
            "direction": (query.get("direction") or ["desc"])[0],
        }
        if observed_at is not None:
            allowed["observed_at"] = software_inventory._utc_iso(
                observed_at.astimezone(dt.timezone.utc)
            )
        try:
            payload = alert_store_get_json(
                f"/software-inventory?{urlencode(allowed)}",
                timeout=10.0,
            )
        except RuntimeError as exc:
            filters = software_inventory.parse_filters(query)
            return HTTPStatus.SERVICE_UNAVAILABLE, software_inventory._empty_payload(
                observed_at or dt.datetime.now(dt.timezone.utc),
                filters,
                error=f"PostgreSQL software inventory unavailable: {exc}",
            )
        items = payload.get("items")
        if isinstance(items, list):
            software_inventory.apply_asset_labels(
                items,
                assets,
                inventory_complete=asset_inventory_complete,
            )
            software_inventory.correlate_asset_operating_systems(
                items,
                items,
                assets=assets,
                observed_at=observed_at or dt.datetime.now(dt.timezone.utc),
            )
            coverage = payload.get("coverage")
            if isinstance(coverage, dict):
                coverage["labeled_visible_records"] = sum(
                    bool(item.get("asset_label"))
                    for item in items
                    if isinstance(item, dict)
                )
                coverage["asset_label_inventory_complete"] = (
                    asset_inventory_complete
                )
                coverage["asset_os_correlated_records"] = sum(
                    bool(item.get("operating_system_association"))
                    for item in items
                    if isinstance(item, dict)
                )
        if not asset_inventory_complete:
            warnings = payload.get("warnings")
            if isinstance(warnings, list):
                warnings.append(
                    "Asset labels are withheld because the complete bounded "
                    "Asset Inventory could not be read."
                )
        return HTTPStatus.OK, payload

    status, payload = software_inventory.build_response(
        Path(SOFTWARE_INVENTORY_STATE_FILE),
        query,
        observed_at=observed_at,
        maximum_bytes=SOFTWARE_INVENTORY_MAX_BYTES,
        assets=assets,
        asset_inventory_complete=asset_inventory_complete,
    )
    if status != HTTPStatus.OK or not isinstance(payload.get("items"), list):
        return status, payload
    if not asset_inventory_complete:
        warnings = payload.get("warnings")
        if isinstance(warnings, list):
            warnings.append(
                "Asset labels are withheld because the complete bounded "
                "Asset Inventory could not be read."
            )
    return status, payload


def resolve_asset_ip(
    value: object,
    observed_at: object,
    inventory: dict | None = None,
) -> dict:
    """Resolve an IP only when one active inventory record claims it."""
    try:
        address = str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return {"status": "not_applicable", "ip": str(value or "")}
    try:
        when = parse_iso_timestamp(observed_at)
        if when.tzinfo is None:
            raise ValueError("timestamp lacks offset")
        when = when.astimezone(dt.timezone.utc)
    except (TypeError, ValueError):
        return {"status": "time_invalid", "ip": address}
    if inventory is None:
        inventory, error = load_asset_inventory_data()
        if error:
            return {"status": "inventory_unavailable", "ip": address}

    matches = []
    for raw in inventory.get("assets", []):
        if not isinstance(raw, dict) or _asset_record_state(raw, when) != "current":
            continue
        identifiers = (
            raw.get("identifiers")
            if isinstance(raw.get("identifiers"), dict)
            else {}
        )
        if address in (identifiers.get("ip") or []):
            matches.append(raw)
    if not matches:
        return {"status": "unmapped", "ip": address}
    if len(matches) > 1:
        return {
            "status": "ambiguous",
            "ip": address,
            "asset_ids": sorted(
                str(item.get("asset_id") or "") for item in matches
            ),
        }
    asset = matches[0]
    identifiers = asset.get("identifiers") or {}
    hostnames = list(identifiers.get("hostname") or [])
    return {
        "status": "resolved" if hostnames else "known_without_hostname",
        "ip": address,
        "asset_id": str(asset.get("asset_id") or ""),
        "hostname": hostnames[0] if hostnames else "",
        "hostnames": hostnames,
        "role": str(asset.get("role") or ""),
        "platform": str(asset.get("platform") or ""),
        "criticality": str(asset.get("criticality") or "unknown"),
        "confidence": str(asset.get("confidence") or "unknown"),
        "valid_from": str(asset.get("valid_from") or ""),
        "valid_until": str(asset.get("valid_until") or ""),
        "source_type": str(asset.get("source_type") or ""),
    }


def dhcp_asset_discovery_response(
    *,
    observed_at: dt.datetime | None = None,
) -> tuple[int, dict]:
    """Return DHCP candidates reconciled against authoritative inventory."""
    now = observed_at or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        now = now.astimezone()
    now = now.astimezone(dt.timezone.utc)
    state, state_error = load_dhcp_asset_discovery_state_data()
    dependencies = DhcpDiscoveryDependencies(
        asset_record_state=_asset_record_state,
        asset_public_record=_asset_public_record,
        parse_timestamp=parse_iso_timestamp,
        format_timestamp=format_iso_timestamp,
        mac_address_scope=_mac_address_scope,
    )
    if state_error:
        return compose_dhcp_discovery_response(
            state=state,
            state_error=state_error,
            inventory={},
            inventory_error="",
            observed_at=now,
            dependencies=dependencies,
        )
    inventory, inventory_error = load_asset_inventory_data()
    return compose_dhcp_discovery_response(
        state=state,
        state_error="",
        inventory=inventory,
        inventory_error=inventory_error,
        observed_at=now,
        dependencies=dependencies,
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


def _beacon_timestamp(beacon: dict[str, object]) -> dt.datetime | None:
    for key in ("generated_at", "history_recorded_at", "last_seen", "timestamp", "exported_at"):
        value = beacon.get(key)
        if not value:
            continue
        try:
            parsed = parse_iso_timestamp(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return parsed.astimezone(dt.timezone.utc)
        except Exception:
            continue
    return None


def _beacon_http_status(beacon: dict[str, object]) -> object:
    previous = beacon.get("relay_previous_failure")
    if isinstance(previous, dict) and previous.get("http_status") not in (None, ""):
        return previous.get("http_status")
    status = beacon.get("status")
    if isinstance(status, int):
        return status
    if isinstance(status, str) and re.fullmatch(r"\d{3}", status.strip()):
        return int(status)
    return None


def _beacon_successful(beacon: dict[str, object]) -> bool:
    if beacon.get("ok") is False:
        return False
    if beacon.get("error"):
        return False
    status = str(beacon.get("status") or "").lower()
    if status in {"error", "failed", "transient_failed", "still_failed"}:
        return False
    return True


def _freshest_existing_path(paths: list[Path]) -> Path | None:
    existing = [path for path in paths if path.exists()]
    if not existing:
        return None
    return max(existing, key=lambda path: path.stat().st_mtime)


def n8n_beacon_history_response(query: dict[str, list[str]]) -> dict[str, object]:
    try:
        hours = max(1, min(168, int((query.get("hours") or ["24"])[0])))
    except ValueError:
        hours = 24
    now = dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(hours=hours)
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

    entries: list[dict[str, object]] = []
    for raw in history:
        if not isinstance(raw, dict):
            continue
        timestamp = _beacon_timestamp(raw)
        if not timestamp or timestamp < cutoff:
            continue
        previous = raw.get("relay_previous_failure") if isinstance(raw.get("relay_previous_failure"), dict) else None
        successful = _beacon_successful(raw) and not previous
        entries.append({
            "timestamp": format_iso_timestamp(timestamp.astimezone(), timespec="milliseconds"),
            "timestamp_utc": format_iso_timestamp(timestamp, timespec="milliseconds", utc_z=True),
            "successful": successful,
            "stage": raw.get("stage") or "unknown",
            "status": raw.get("status") or "unknown",
            "message_type": raw.get("message_type") or "",
            "relay_host": raw.get("relay_host") or "",
            "alert_count": raw.get("alert_count"),
            "posted_webhook_alerts": raw.get("posted_webhook_alerts"),
            "rule_name": raw.get("rule_name") or raw.get("first_rule") or "",
            "http_status": _beacon_http_status(raw),
            "error": raw.get("error") or (previous or {}).get("summary") or "",
            "previous_failure": previous,
        })
    entries.sort(key=lambda item: str(item.get("timestamp_utc") or ""))

    successful_entries = [entry for entry in entries if entry.get("successful")]
    gaps: list[dict[str, object]] = []
    previous_success: dict[str, object] | None = None
    for entry in successful_entries:
        current_ts = _beacon_timestamp({"generated_at": entry.get("timestamp_utc")})
        previous_ts = _beacon_timestamp({"generated_at": previous_success.get("timestamp_utc")}) if previous_success else None
        if previous_ts and current_ts:
            minutes = (current_ts - previous_ts).total_seconds() / 60
            if minutes > 10:
                gaps.append({
                    "start": previous_success.get("timestamp"),
                    "end": entry.get("timestamp"),
                    "minutes": round(minutes, 1),
                    "status": "closed",
                })
        previous_success = entry
    if previous_success:
        last_success_ts = _beacon_timestamp({"generated_at": previous_success.get("timestamp_utc")})
        if last_success_ts:
            minutes = (now - last_success_ts).total_seconds() / 60
            if minutes > 10:
                gaps.append({
                    "start": previous_success.get("timestamp"),
                    "end": format_iso_timestamp(now.astimezone(), timespec="milliseconds"),
                    "minutes": round(minutes, 1),
                    "status": "open",
                })

    pipeline: dict[str, object] = {"available": False, "stages": [], "disk": {}}
    try:
        metrics_payload = alert_store_get_json("/metrics", timeout=2.0)
        pipeline = dict((metrics_payload.get("metrics") or {}).get("pipeline") or {})
        pipeline["available"] = True
    except RuntimeError as exc:
        pipeline["error"] = str(exc)

    return {
        "ok": True,
        "window_hours": hours,
        "generated_at": now_iso_local(),
        "history_source": str(history_path) if history_path else None,
        "entries": entries,
        "gaps": gaps,
        "pcap": pcap_workflow_health_response(),
        "pipeline": pipeline,
        "summary": {
            "total": len(entries),
            "successful": len(successful_entries),
            "unsuccessful": len(entries) - len(successful_entries),
            "gap_count": len(gaps),
            "latest": entries[-1] if entries else None,
        },
    }


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
    try:
        token = ADMIN_TOKEN_FILE.read_text(encoding="utf-8").strip()
        if re.fullmatch(r"[a-f0-9]{64}", token):
            return token
    except Exception:
        pass
    ADMIN_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    token = os.urandom(32).hex()
    ADMIN_TOKEN_FILE.write_text(token, encoding="utf-8")
    try:
        ADMIN_TOKEN_FILE.chmod(0o600)
    except Exception:
        pass
    return token


def load_admin_password_record() -> dict | None:
    """Load the local admin password hash record, if configured."""
    try:
        data = json.loads(ADMIN_PASSWORD_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("algorithm") == "pbkdf2_sha256":
            return data
    except Exception:
        pass
    return None


def admin_password_configured() -> bool:
    return load_admin_password_record() is not None


def verify_admin_password(password: str) -> bool:
    record = load_admin_password_record()
    if not record or not password:
        return False
    try:
        iterations = int(record.get("iterations", 0))
        salt = bytes.fromhex(str(record.get("salt", "")))
        expected = bytes.fromhex(str(record.get("hash", "")))
        if iterations < 200_000 or not salt or not expected:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def admin_session_hash(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def load_admin_sessions() -> dict:
    try:
        data = json.loads(ADMIN_SESSIONS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_admin_sessions(sessions: dict) -> None:
    ADMIN_STATE_DIR.mkdir(parents=True, exist_ok=True)
    ADMIN_SESSIONS_FILE.write_text(json.dumps(sessions, indent=2, sort_keys=True), encoding="utf-8")
    try:
        ADMIN_SESSIONS_FILE.chmod(0o600)
    except Exception:
        pass


def prune_admin_sessions(sessions: dict | None = None) -> dict:
    sessions = load_admin_sessions() if sessions is None else sessions
    now_ts = int(dt.datetime.now().timestamp())
    pruned = {
        sid_hash: meta
        for sid_hash, meta in sessions.items()
        if isinstance(meta, dict) and int(meta.get("expires_at", 0) or 0) > now_ts
    }
    if pruned != sessions:
        save_admin_sessions(pruned)
    return pruned


def create_admin_session(client_ip: str) -> str:
    now_ts = int(dt.datetime.now().timestamp())
    session_id = secrets.token_urlsafe(32)
    sessions = prune_admin_sessions()
    sessions[admin_session_hash(session_id)] = {
        "created_at": now_ts,
        "expires_at": now_ts + ADMIN_SESSION_TTL_SECONDS,
        "client_ip": client_ip,
    }
    save_admin_sessions(sessions)
    return session_id


def destroy_admin_session(session_id: str) -> None:
    if not session_id:
        return
    sessions = load_admin_sessions()
    sessions.pop(admin_session_hash(session_id), None)
    save_admin_sessions(sessions)


def resource_library_id_for(path: Path) -> str:
    return hashlib.sha1(str(path).encode("utf-8")).hexdigest()[:12]


def find_resource_library_pdf(resource_id: str, source_path: str = "") -> tuple[Path, str, Path] | None:
    if not re.fullmatch(r"[a-f0-9]{12}", resource_id or ""):
        return None

    # Preferred path: the static Resource Library card posts its exact source path.
    # This avoids macOS launchd/TCC cases where the portal process can access a
    # specific file path but cannot enumerate ~/Documents recursively.
    if source_path:
        try:
            candidate = Path(source_path).expanduser().resolve()
        except Exception:
            candidate = None
        if candidate and candidate.suffix.lower() == ".pdf" and candidate.name and not candidate.name.startswith("._"):
            for category, root in RESOURCE_LIBRARY_SOURCES:
                try:
                    rel = candidate.relative_to(root.resolve())
                except ValueError:
                    continue
                if resource_library_id_for(candidate) == resource_id and candidate.is_file():
                    return candidate, category, rel

    # Fallback for interactive/local runs where recursive Documents access works.
    for category, root in RESOURCE_LIBRARY_SOURCES:
        if not root.exists():
            continue
        for src in root.rglob("*.pdf"):
            if any(part == "__MACOSX" for part in src.parts) or src.name.startswith("._") or not src.is_file():
                continue
            rel = src.relative_to(root)
            if category == "CheatSheets" and rel.parts and rel.parts[0] == "SANS_Posters":
                continue
            if resource_library_id_for(src) == resource_id:
                return src, category, rel
    return None


def unique_destination(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    for i in range(1, 1000):
        candidate = path.with_name(f"{stem} ({i}){suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Could not find unique removal destination for {path.name}")


def refresh_resource_library() -> None:
    env = {**os.environ, "PATH": ADMIN_COMMAND_ENV.get("PATH", os.environ.get("PATH", ""))}
    subprocess.run([sys.executable, str(RESOURCE_LIBRARY_BUILDER)], check=True, timeout=180, env=env, capture_output=True, text=True)
    subprocess.run([sys.executable, str(RESOURCE_LIBRARY_SYNC)], check=True, timeout=180, env=env, capture_output=True, text=True)


def load_resource_library_metadata() -> dict:
    try:
        data = json.loads(RESOURCE_LIBRARY_METADATA_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_resource_library_metadata(data: dict) -> None:
    RESOURCE_LIBRARY_METADATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = RESOURCE_LIBRARY_METADATA_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(RESOURCE_LIBRARY_METADATA_FILE)


def clean_resource_tags(values) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    if isinstance(values, str):
        values = re.split(r"[,;\n]+", values)
    if not isinstance(values, list):
        return []
    for value in values:
        tag = re.sub(r"\s+", " ", str(value)).strip()[:40]
        if not tag:
            continue
        key = tag.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(tag)
    return out[:12]


def sanitize_resource_filename(name: str, original_suffix: str) -> str:
    """Return a safe basename while preserving the source file extension.

    Users rename the visible title in the web UI; the actual file on disk must
    keep its original extension. If they type another extension, strip it and
    restore the original suffix instead of producing names like `.txt.pdf`.
    """
    suffix = original_suffix if original_suffix.startswith(".") else f".{original_suffix}"
    suffix = suffix or ".pdf"
    cleaned = re.sub(r"[/:\\]+", "-", name).strip().strip(".")
    cleaned = re.sub(r"\s+", " ", cleaned)[:120].strip()
    if not cleaned:
        raise ValueError("New filename is empty")
    if Path(cleaned).suffix:
        cleaned = cleaned[: -len(Path(cleaned).suffix)].rstrip(" .")
    if not cleaned:
        raise ValueError("New filename is empty")
    cleaned = f"{cleaned}{suffix}"
    if cleaned.startswith("._") or cleaned in {".", ".."}:
        raise ValueError("Invalid filename")
    return cleaned


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
    data = load_resource_library_metadata()
    favs = data.get("_favorites", [])
    if not isinstance(favs, list):
        return []
    return sorted({str(x) for x in favs if re.fullmatch(r"[a-f0-9]{12}", str(x))})


def set_resource_favorite(resource_id: str, favorite: bool) -> tuple[bool, dict]:
    if not re.fullmatch(r"[a-f0-9]{12}", resource_id or ""):
        return False, {"ok": False, "error": "Invalid resource id"}
    data = load_resource_library_metadata()
    favs = set(resource_favorites())
    if favorite:
        favs.add(resource_id)
    else:
        favs.discard(resource_id)
    data["_favorites"] = sorted(favs)
    save_resource_library_metadata(data)
    queue_resource_action({"action": "refresh", "reason": "favorite", "id": resource_id})
    trigger_resource_library_worker()
    return True, {"ok": True, "favorite": favorite, "favorites": sorted(favs)}


def set_resource_tags(resource_id: str, tags) -> tuple[bool, dict]:
    if not re.fullmatch(r"[a-f0-9]{12}", resource_id or ""):
        return False, {"ok": False, "error": "Invalid resource id"}
    cleaned = clean_resource_tags(tags)
    data = load_resource_library_metadata()
    entry = data.get(resource_id, {}) if isinstance(data.get(resource_id, {}), dict) else {}
    entry["custom_tags"] = cleaned
    data[resource_id] = entry
    save_resource_library_metadata(data)
    queue_resource_action({"action": "refresh", "reason": "tags", "id": resource_id})
    trigger_resource_library_worker()
    return True, {"ok": True, "tags": cleaned, "queued": True}


def rename_resource_file(resource_id: str, source_path: str, new_name: str) -> tuple[bool, dict]:
    found = find_resource_library_pdf(resource_id, source_path)
    if not found:
        return False, {"ok": False, "error": "Resource not found"}
    src, _category, _rel = found
    try:
        safe_name = sanitize_resource_filename(new_name, src.suffix)
    except ValueError as exc:
        return False, {"ok": False, "error": str(exc)}
    dest = src.with_name(safe_name)
    if dest.resolve() == src.resolve():
        return False, {"ok": False, "error": f"Rename aborted: the file is already named '{dest.name}'. No files were changed."}
    if dest.exists():
        return False, {"ok": False, "error": f"Rename aborted: a file named '{dest.name}' already exists. No files were changed."}
    display_title = re.sub(r"[_-]+", " ", dest.stem).strip() or dest.stem
    try:
        shutil.move(str(src), str(dest))
    except PermissionError as exc:
        data = queue_resource_action({"action": "rename", "id": resource_id, "source": str(src), "new_name": safe_name, "portal_error": str(exc)})
        trigger_resource_library_worker()
        data.update({"display_title": display_title, "source": str(src), "target_source": str(dest), "refresh_after_ms": 65000})
        return True, data
    except Exception as exc:
        return False, {"ok": False, "error": f"Rename failed: {exc}"}
    # Preserve metadata across the source-path-derived ID change.
    data = load_resource_library_metadata()
    old_entry = data.pop(resource_id, None)
    new_id = resource_library_id_for(dest)
    if isinstance(old_entry, dict):
        data[new_id] = old_entry
    favs = data.get("_favorites", [])
    if isinstance(favs, list) and resource_id in favs:
        data["_favorites"] = sorted({new_id if x == resource_id else str(x) for x in favs})
    save_resource_library_metadata(data)
    try:
        refresh_resource_library()
    except Exception as exc:
        return True, {"ok": True, "warning": f"Renamed file on disk, but Resource Library refresh failed: {exc}", "new_id": new_id, "source": str(dest), "display_title": display_title, "renamed_on_disk": True}
    return True, {"ok": True, "new_id": new_id, "source": str(dest), "display_title": display_title, "renamed_on_disk": True, "refresh_after_ms": 1200}


def queue_resource_removal(resource_id: str, source_path: str, error: str) -> dict:
    data = queue_resource_action({"action": "remove", "id": resource_id, "source": source_path, "portal_error": error})
    trigger_resource_library_worker()
    data.update({"message": "Removal queued for the Hermes Resource Library worker.", "source": source_path})
    return data


def move_resource_to_removal(resource_id: str, source_path: str = "") -> tuple[bool, dict]:
    found = find_resource_library_pdf(resource_id, source_path)
    if not found:
        return False, {"ok": False, "error": "Resource not found"}
    src, category, rel = found
    dest = unique_destination(RESOURCE_LIBRARY_REMOVAL_DIR / category / rel)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.move(str(src), str(dest))
    except PermissionError as exc:
        return True, queue_resource_removal(resource_id, str(src), str(exc))
    except Exception as exc:
        return False, {"ok": False, "error": f"Move failed: {exc}"}
    try:
        refresh_resource_library()
    except Exception as exc:
        return True, {
            "ok": True,
            "warning": f"Moved file, but Resource Library refresh failed: {exc}",
            "moved_to": str(dest),
            "title": src.name,
        }
    return True, {"ok": True, "moved_to": str(dest), "title": src.name}


def parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    cookies: dict[str, str] = {}
    if not cookie_header:
        return cookies
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        cookies[name.strip()] = value.strip()
    return cookies


def admin_session_cookie_header(session_id: str, max_age: int | None = None) -> str:
    max_age = ADMIN_SESSION_TTL_SECONDS if max_age is None else max_age
    return f"{ADMIN_SESSION_COOKIE}={session_id}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Strict"


def expired_admin_session_cookie_header() -> str:
    return f"{ADMIN_SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"


def read_prompt_file(path: Path, label: str) -> dict:
    """Read one allowlisted settings prompt without accepting a caller-supplied path."""
    try:
        prompt = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        prompt = ""
    except Exception as exc:
        return {"ok": False, "error": f"Could not read {label} prompt: {exc}", "path": str(path)}
    return {"ok": True, "prompt": prompt, "path": str(path)}


def read_soc_analyst_prompt() -> dict:
    """Return the current SOC Analyst system prompt shown on the Settings page."""
    return read_prompt_file(SOC_ANALYST_PROMPT_FILE, "SOC Analyst")


def read_siem_engineer_prompt() -> dict:
    """Return the current SIEM Engineer system prompt shown on the Settings page."""
    return read_prompt_file(SIEM_ENGINEER_PROMPT_FILE, "SIEM Engineer")


def read_threat_hunter_prompt() -> dict:
    """Return the current Threat Hunter system prompt shown on the Settings page."""
    return read_prompt_file(THREAT_HUNTER_PROMPT_FILE, "Threat Hunter")


def read_cyber_threat_intel_prompt() -> dict:
    """Return the current Cyber Threat Intel Analyst system prompt shown on the Settings page."""
    return read_prompt_file(CYBER_THREAT_INTEL_PROMPT_FILE, "Cyber Threat Intel")


def read_incident_responder_prompt() -> dict:
    """Return the current Incident Responder system prompt shown on the Settings page."""
    return read_prompt_file(INCIDENT_RESPONDER_PROMPT_FILE, "Incident Responder")


def read_settings_prompt(api_path: str) -> dict:
    """Read a primary or reviewer prompt selected only from the fixed API route map."""
    entry = SOC_SETTINGS_PROMPT_FILES.get(api_path)
    if entry is None:
        return {"ok": False, "error": "Unknown SOC settings prompt route."}
    label, path = entry
    return read_prompt_file(path, label)


def agent_memory_files() -> dict[str, tuple[str, Path]]:
    """Return the only agent memory files the read-only Settings API may expose."""
    return {
        "soc-analyst": ("SOC Analyst Memory", SOC_ANALYST_MEMORY_FILE),
        "incident-responder": ("Incident Responder Memory", INCIDENT_RESPONDER_MEMORY_FILE),
        "siem-engineer": ("SIEM Engineer Memory", SIEM_ENGINEER_MEMORY_FILE),
        "cyber-threat-intel": ("Cyber Threat Intel Memory", CYBER_THREAT_INTEL_MEMORY_FILE),
        "threat-hunter": ("Threat Hunter Memory", THREAT_HUNTER_MEMORY_FILE),
        "shared": ("Shared Agent Memory", SHARED_AGENT_MEMORY_FILE),
    }


def read_agent_memory(memory_key: object) -> tuple[int, dict]:
    """Read one allowlisted Markdown memory file without permitting path input."""
    key = str(memory_key or "").strip().lower()
    entry = agent_memory_files().get(key)
    if entry is None:
        return HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Unknown agent memory key."}

    label, path = entry
    try:
        resolved_dir = AGENT_MEMORY_DIR.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        resolved_path.relative_to(resolved_dir)
        stat = resolved_path.stat()
        if not resolved_path.is_file():
            raise FileNotFoundError(str(resolved_path))
        if stat.st_size > AGENT_MEMORY_VIEW_MAX_BYTES:
            return HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {
                "ok": False,
                "key": key,
                "label": label,
                "path": str(path),
                "bytes": stat.st_size,
                "read_only": True,
                "error": f"{label} exceeds the {AGENT_MEMORY_VIEW_MAX_BYTES}-byte viewer limit.",
            }
        content = resolved_path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return HTTPStatus.NOT_FOUND, {"ok": False, "error": f"{label} does not exist."}
    except ValueError:
        return HTTPStatus.FORBIDDEN, {"ok": False, "error": "Agent memory path escaped the configured memory directory."}
    except Exception as exc:
        return HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": f"Could not read {label}: {exc}"}

    modified_at = dt.datetime.fromtimestamp(stat.st_mtime).astimezone().isoformat(timespec="seconds").replace("T", "  ")
    return HTTPStatus.OK, {
        "ok": True,
        "key": key,
        "label": label,
        "path": str(path),
        "content": content,
        "bytes": stat.st_size,
        "modified_at": modified_at,
        "read_only": True,
    }


def save_prompt_file(prompt: object, path: Path, label: str) -> tuple[bool, dict]:
    """Atomically save an editable SOC settings prompt."""
    normalized = str(prompt or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not normalized:
        return False, {"ok": False, "error": f"{label} prompt cannot be empty.", "path": str(path)}
    if len(normalized.encode("utf-8")) > SOC_ANALYST_PROMPT_MAX_BYTES:
        return False, {"ok": False, "error": f"{label} prompt exceeds {SOC_ANALYST_PROMPT_MAX_BYTES} bytes.", "path": str(path)}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(normalized + "\n", encoding="utf-8")
        try:
            tmp.chmod(0o600)
        except Exception:
            pass
        tmp.replace(path)
    except Exception as exc:
        return False, {"ok": False, "error": f"Could not save {label} prompt: {exc}", "path": str(path)}
    return True, {"ok": True, "message": f"{label} prompt saved.", "path": str(path), "bytes": len((normalized + "\n").encode("utf-8"))}


def save_soc_analyst_prompt(prompt: object) -> tuple[bool, dict]:
    """Atomically save the editable SOC Analyst system prompt."""
    return save_prompt_file(prompt, SOC_ANALYST_PROMPT_FILE, "SOC Analyst")


def save_siem_engineer_prompt(prompt: object) -> tuple[bool, dict]:
    """Atomically save the editable SIEM Engineer system prompt."""
    return save_prompt_file(prompt, SIEM_ENGINEER_PROMPT_FILE, "SIEM Engineer")


def save_threat_hunter_prompt(prompt: object) -> tuple[bool, dict]:
    """Atomically save the editable Threat Hunter system prompt."""
    return save_prompt_file(prompt, THREAT_HUNTER_PROMPT_FILE, "Threat Hunter")


def save_cyber_threat_intel_prompt(prompt: object) -> tuple[bool, dict]:
    """Atomically save the editable Cyber Threat Intel Analyst system prompt."""
    return save_prompt_file(prompt, CYBER_THREAT_INTEL_PROMPT_FILE, "Cyber Threat Intel")


def save_incident_responder_prompt(prompt: object) -> tuple[bool, dict]:
    """Atomically save the editable Incident Responder system prompt."""
    return save_prompt_file(prompt, INCIDENT_RESPONDER_PROMPT_FILE, "Incident Responder")


def save_settings_prompt(api_path: str, prompt: object) -> tuple[bool, dict]:
    """Save a primary or reviewer prompt selected only from the fixed API route map."""
    entry = SOC_SETTINGS_PROMPT_FILES.get(api_path)
    if entry is None:
        return False, {"ok": False, "error": "Unknown SOC settings prompt route."}
    label, path = entry
    return save_prompt_file(prompt, path, label)


SOC_AI_SETTINGS_LOCK = threading.RLock()


def normalize_soc_ai_settings(payload: dict | None) -> tuple[bool, dict]:
    """Validate and normalize editable SOC AI model routing settings."""
    policy = SocAiSettingsNormalizationPolicy(
        defaults=default_soc_ai_settings,
        maxmind_databases=MAXMIND_GEOIP_DATABASE_SETTINGS,
        codex_efforts=CODEX_CLI_REASONING_EFFORTS,
        hermes_effort=HERMES_AGENT_REASONING_EFFORT,
        codex_catalog=CODEX_CLI_MODEL_CATALOG,
        severity_thresholds=SOC_ANALYSIS_SEVERITY_THRESHOLDS,
        openclaw_ollama_urls=OPENCLAW_SUPPORTED_OLLAMA_URLS,
        normalized_model_list=_normalized_model_list,
        boolean_setting=_boolean_setting,
        derive_model_mode=_derive_model_mode,
        valid_cli_path=_valid_cli_executable_path,
        valid_provider_model=_valid_provider_model,
        valid_openclaw_model=_valid_openclaw_model,
        normalize_codex_models=_normalize_codex_cli_models,
        enabled_routes=_enabled_agent_model_routes,
        normalize_primary_models=_normalize_agent_models,
        normalize_reviewer_models=_normalize_agent_second_opinion_models,
        normalize_adjudicator_models=_normalize_agent_adjudicator_models,
    )
    return normalize_ai_settings(payload, policy)


def maxmind_geoip_database_status(settings: dict, database_type: str = "city") -> dict:
    """Expose one database's readiness without reading or returning contents."""
    if database_type not in MAXMIND_GEOIP_DATABASE_SETTINGS:
        raise ValueError(f"Unsupported MaxMind database type: {database_type}")
    setting_key, default_path = MAXMIND_GEOIP_DATABASE_SETTINGS[database_type]
    configured = str(settings.get(setting_key) or "").strip()
    if database_type == "city" and not configured:
        configured = str(settings.get("maxmind_geoip_db_path") or "").strip()
    configured = configured or default_path
    path = Path(configured).expanduser()
    status = {
        "database_type": database_type,
        "setting_key": setting_key,
        "state": "missing",
        "configured_path": configured,
        "filename": path.name,
    }
    try:
        stat = path.stat()
    except FileNotFoundError:
        return status
    except OSError:
        status["state"] = "unreadable"
        return status
    if not path.is_file() or not os.access(path, os.R_OK):
        status["state"] = "unreadable"
        return status
    status.update({
        "state": "ready",
        "size_bytes": stat.st_size,
        "modified_at": dt.datetime.fromtimestamp(stat.st_mtime).astimezone().isoformat().replace("T", "  "),
    })
    return status


def maxmind_geoip_databases_status(settings: dict) -> dict:
    """Return independent readiness for ASN, City, and Country databases."""
    return {
        database_type: maxmind_geoip_database_status(settings, database_type)
        for database_type in MAXMIND_GEOIP_DATABASE_SETTINGS
    }


def read_soc_ai_settings() -> dict:
    """Return the current SOC AI model-routing settings."""
    with SOC_AI_SETTINGS_LOCK:
        try:
            raw = json.loads(SOC_AI_SETTINGS_FILE.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raw = {}
        except Exception as exc:
            return {"ok": False, "error": f"Could not read SOC AI settings: {exc}", "path": str(SOC_AI_SETTINGS_FILE)}
    ok, normalized = normalize_soc_ai_settings(raw)
    if not ok:
        return {
            "ok": False,
            "error": str(
                (normalized.get("error") if isinstance(normalized, dict) else "")
                or "SOC AI settings validation failed."
            ),
            "path": str(SOC_AI_SETTINGS_FILE),
        }
    return {
        "ok": True,
        "settings": normalized,
        "geoip_databases": maxmind_geoip_databases_status(normalized),
        # Compatibility alias for older dashboard builds during rolling deploys.
        "geoip_database": maxmind_geoip_database_status(normalized, "city"),
        "path": str(SOC_AI_SETTINGS_FILE),
    }


def list_ollama_models() -> list[str]:
    """Return locally installed Ollama model names from `ollama ls`."""
    commands = [
        ["/opt/homebrew/bin/ollama", "ls"],
        ["/usr/local/bin/ollama", "ls"],
        ["ollama", "ls"],
    ]
    output = ""
    for command in commands:
        try:
            proc = subprocess.run(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                env=ADMIN_COMMAND_ENV,
            )
        except Exception:
            continue
        if proc.returncode == 0 and proc.stdout.strip():
            output = proc.stdout
            break
    models: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("name"):
            continue
        name = stripped.split()[0].strip()
        if name and name not in models:
            models.append(name)
    return models


def _ollama_context_length(model_info: object) -> int:
    """Return the largest declared context window from Ollama model metadata."""
    if not isinstance(model_info, dict):
        return 0
    lengths: list[int] = []
    for key, value in model_info.items():
        if not str(key).endswith(".context_length"):
            continue
        try:
            lengths.append(max(0, int(value)))
        except (TypeError, ValueError):
            continue
    return max(lengths, default=0)


def classify_ollama_model_compatibility(model: str, metadata: object) -> dict:
    """Assess only capabilities the current bounded SOC analysis exchange requires."""
    if not isinstance(metadata, dict):
        return {
            "compatible": False,
            "status": "unverified",
            "reasons": ["Ollama did not return capability metadata for this model."],
            "capabilities": [],
            "context_length": 0,
        }

    capabilities = sorted({
        str(item).strip().lower()
        for item in metadata.get("capabilities", [])
        if str(item).strip()
    }) if isinstance(metadata.get("capabilities"), list) else []
    context_length = _ollama_context_length(metadata.get("model_info"))
    reasons: list[str] = []

    if "completion" not in capabilities:
        if "image" in capabilities:
            reasons.append(
                "Image-generation only: this model cannot return the text and JSON analysis required by Onion Sentinel."
            )
        elif "embedding" in capabilities:
            reasons.append(
                "Embedding-only: this model cannot generate the text and JSON analysis required by Onion Sentinel."
            )
        else:
            reasons.append(
                "No text-completion capability was reported, so the model cannot produce an Onion Sentinel analysis."
            )
    if not str(metadata.get("template") or "").strip():
        reasons.append(
            "No chat template was reported, so the model cannot accept the system and analyst messages used by Onion Sentinel."
        )
    if context_length and context_length < OLLAMA_MODEL_MIN_CONTEXT_TOKENS:
        reasons.append(
            f"The {context_length:,}-token context window is below Onion Sentinel's "
            f"{OLLAMA_MODEL_MIN_CONTEXT_TOKENS:,}-token operational minimum."
        )

    return {
        "compatible": not reasons,
        "status": "compatible" if not reasons else "incompatible",
        "reasons": reasons,
        "capabilities": capabilities,
        "context_length": context_length,
    }


def ollama_model_compatibility(model: str, ollama_url: str) -> dict:
    """Read bounded local Ollama metadata and cache the compatibility decision."""
    cache_key = (ollama_url.rstrip("/"), model)

    def compute() -> dict:
        endpoint = cache_key[0] + "/api/show"
        request = urllib_request.Request(
            endpoint,
            data=json.dumps({"model": model}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib_request.urlopen(request, timeout=4) as response:
                metadata = read_bounded_json(response, max_bytes=OLLAMA_MODEL_SHOW_MAX_BYTES)
        except Exception:
            return classify_ollama_model_compatibility(model, None)
        return classify_ollama_model_compatibility(model, metadata)

    return OLLAMA_MODEL_COMPATIBILITY_CACHE.get_or_compute(cache_key, compute)


def ollama_models_response(force_refresh: bool = False) -> dict:
    settings = read_soc_ai_settings().get("settings") or default_soc_ai_settings()
    installed_models = list_ollama_models()
    enabled_models = _normalized_model_list(settings.get("enabled_ollama_models"))
    models = list(installed_models)
    for configured_model in enabled_models:
        if configured_model not in models:
            models.append(configured_model)
    if force_refresh:
        OLLAMA_MODEL_COMPATIBILITY_CACHE.clear()
    ollama_url = str(settings.get("ollama_url") or "http://127.0.0.1:11434").rstrip("/")
    installed_set = set(installed_models)

    def assess(model: str) -> tuple[str, dict]:
        if model not in installed_set:
            return model, {
                "compatible": False,
                "status": "unavailable",
                "reasons": ["This model is configured but is not installed locally, so Onion Sentinel cannot run it."],
                "capabilities": [],
                "context_length": 0,
            }
        return model, ollama_model_compatibility(model, ollama_url)

    compatibility: dict[str, dict] = {}
    if models:
        # Metadata reads are independent local requests. A small fixed pool keeps
        # one unhealthy model endpoint from serially delaying the Settings page.
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(models))) as executor:
            for model, assessment in executor.map(assess, models):
                compatibility[model] = assessment
    current = enabled_models[0] if enabled_models else str(settings.get("ollama_model") or "").strip()
    return {
        "ok": True,
        "models": models,
        "installed_models": installed_models,
        "enabled_models": enabled_models,
        "compatibility": compatibility,
        "selected": current,
        "command": "ollama ls",
    }


def _write_soc_ai_settings(normalized: dict) -> tuple[bool, dict]:
    """Write one fully normalized settings document while the caller holds the lock."""
    try:
        SOC_AI_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = SOC_AI_SETTINGS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            tmp.chmod(0o600)
        except Exception:
            pass
        tmp.replace(SOC_AI_SETTINGS_FILE)
    except Exception as exc:
        return False, {"ok": False, "error": f"Could not save SOC AI settings: {exc}", "path": str(SOC_AI_SETTINGS_FILE)}
    return True, {
        "ok": True,
        "message": "SOC AI model and MaxMind GeoIP settings saved.",
        "settings": normalized,
        "geoip_databases": maxmind_geoip_databases_status(normalized),
        "geoip_database": maxmind_geoip_database_status(normalized, "city"),
        "path": str(SOC_AI_SETTINGS_FILE),
    }


def _resolve_cli_harness_for_settings(
    configured: object,
    basename: str,
) -> Path | None:
    """Resolve one harness without executing it, in the runner's fixed order."""
    executable = str(configured or basename).strip()
    path = Path(executable)
    if path.is_absolute():
        candidates = [path]
    else:
        candidates: list[Path] = []
        discovered = shutil.which(basename)
        if discovered:
            candidates.append(Path(discovered))
        candidates.extend([
            HOME / ".local" / "bin" / basename,
            Path("/opt/homebrew/bin") / basename,
            Path("/usr/local/bin") / basename,
        ])
    seen: set[str] = set()
    for candidate in candidates:
        candidate_text = str(candidate)
        if candidate_text in seen:
            continue
        seen.add(candidate_text)
        if (
            candidate.name == basename
            and candidate.is_file()
            and os.access(candidate, os.X_OK)
        ):
            return candidate
    return None


def _hermes_auth_readiness_error() -> str:
    """Return a safe operator-facing error for the dedicated Hermes credential."""
    try:
        metadata = DEFAULT_HERMES_AUTH_FILE.lstat()
    except FileNotFoundError:
        return (
            "Hermes Agent authentication is unavailable at "
            "~/n8n-local/private/hermes-agent/auth.json."
        )
    except OSError:
        return "Hermes Agent authentication file could not be inspected."
    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return "Hermes Agent authentication must be a regular, non-symlink file."
    if mode != 0o600:
        return (
            "Hermes Agent authentication permissions are unsafe; "
            "set the file mode to 0600."
        )
    if metadata.st_size <= 0 or metadata.st_size > HERMES_AUTH_MAX_BYTES:
        return "Hermes Agent authentication file is empty or exceeds 2 MiB."
    descriptor = -1
    try:
        descriptor = os.open(
            DEFAULT_HERMES_AUTH_FILE,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        opened_metadata = os.fstat(descriptor)
        opened_mode = stat.S_IMODE(opened_metadata.st_mode)
        if (
            not stat.S_ISREG(opened_metadata.st_mode)
            or opened_mode != 0o600
        ):
            return (
                "Hermes Agent authentication must remain a regular "
                "owner-only file."
            )
        chunks: list[bytes] = []
        remaining = HERMES_AUTH_MAX_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except OSError:
        return "Hermes Agent authentication file is not safely readable."
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not raw or len(raw) > HERMES_AUTH_MAX_BYTES:
        return "Hermes Agent authentication file is empty or exceeds 2 MiB."
    try:
        auth_store = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError):
        return "Hermes Agent authentication file is not valid bounded JSON."
    if not isinstance(auth_store, dict):
        return "Hermes Agent authentication JSON root must be an object."
    providers = auth_store.get("providers")
    provider_state = (
        providers.get("openai-codex")
        if isinstance(providers, dict)
        else None
    )
    credential_pool = auth_store.get("credential_pool")
    pool_entries = (
        credential_pool.get("openai-codex")
        if isinstance(credential_pool, dict)
        else None
    )
    pool_is_valid = isinstance(pool_entries, list) and not any(
        not isinstance(entry, dict)
        or (
            entry.get("provider") is not None
            and str(entry.get("provider")).strip() != "openai-codex"
        )
        for entry in pool_entries
    )
    if isinstance(pool_entries, list) and not pool_is_valid:
        return "Hermes Agent openai-codex credential pool is invalid."
    has_provider = isinstance(provider_state, dict) and bool(provider_state)
    has_pool = pool_is_valid and bool(pool_entries)
    if not (has_provider or has_pool):
        return (
            "Hermes Agent authentication does not contain dedicated "
            "openai-codex credentials."
        )
    return ""


def _enabled_cli_harnesses_ready(settings: dict) -> tuple[bool, str]:
    """Fail a settings save when an enabled harness cannot start."""
    for enabled_key, path_key, basename, label in (
        ("hermes_agent_enabled", "hermes_agent_path", "hermes", "Hermes Agent"),
        ("openclaw_enabled", "openclaw_path", "openclaw", "OpenClaw"),
    ):
        if not _boolean_setting(settings.get(enabled_key)):
            continue
        if _resolve_cli_harness_for_settings(settings.get(path_key), basename) is None:
            return False, (
                f"{label} is enabled but its executable is unavailable. "
                f"Install {basename} or configure an executable absolute path."
            )
        if basename == "hermes":
            if auth_error := _hermes_auth_readiness_error():
                return False, auth_error
    return True, ""


def save_soc_ai_settings(payload: object) -> tuple[bool, dict]:
    """Atomically save the complete SOC AI model-routing configuration."""
    with SOC_AI_SETTINGS_LOCK:
        ok, normalized = normalize_soc_ai_settings(payload if isinstance(payload, dict) else {})
        if not ok:
            return False, normalized
        ready, readiness_error = _enabled_cli_harnesses_ready(normalized)
        if not ready:
            return False, {"ok": False, "error": readiness_error}
        return _write_soc_ai_settings(normalized)


def save_soc_agent_model(payload: object) -> tuple[bool, dict]:
    """Atomically update one agent's primary, reviewer, and adjudicator routes."""
    payload = payload if isinstance(payload, dict) else {}
    role = str(payload.get("role") or "").strip()
    model_route = str(payload.get("model_route") or payload.get("model") or "").strip()[:260]
    second_model_route = str(
        payload.get("second_opinion_model_route")
        or payload.get("second_opinion_model")
        or ""
    ).strip()[:260]
    adjudicator_model_route = str(
        payload.get("adjudicator_model_route")
        or payload.get("adjudicator_model")
        or ""
    ).strip()[:260]
    if role not in CYBER_SECURITY_AGENT_ROLES:
        return False, {"ok": False, "error": "Cyber Security Agent role is invalid."}
    with SOC_AI_SETTINGS_LOCK:
        try:
            raw = json.loads(SOC_AI_SETTINGS_FILE.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raw = {}
        except Exception as exc:
            return False, {"ok": False, "error": f"Could not read SOC AI settings: {exc}", "path": str(SOC_AI_SETTINGS_FILE)}
        ok, current = normalize_soc_ai_settings(raw)
        if not ok:
            return False, current
        ready, readiness_error = _enabled_cli_harnesses_ready(current)
        if not ready:
            return False, {"ok": False, "error": readiness_error}
        enabled_routes = _enabled_agent_model_routes(
            current["enabled_ollama_models"],
            current["codex_cli_models"],
            hermes_agent_enabled=current["hermes_agent_enabled"],
            hermes_agent_model=current["hermes_agent_model"],
            hermes_agent_reasoning_effort=current["hermes_agent_reasoning_effort"],
            openclaw_enabled=current["openclaw_enabled"],
            openclaw_model=current["openclaw_model"],
            openclaw_reasoning_effort=current["openclaw_reasoning_effort"],
        )
        if model_route not in enabled_routes:
            return False, {
                "ok": False,
                "error": "That model is not enabled. Save the global model roster before assigning it to an agent.",
            }
        if second_model_route and second_model_route not in enabled_routes:
            return False, {
                "ok": False,
                "error": "That second-opinion model is not enabled. Save the global model roster first.",
            }
        if adjudicator_model_route and adjudicator_model_route not in enabled_routes:
            return False, {
                "ok": False,
                "error": "That adjudicator model is not enabled. Save the global model roster first.",
            }
        if (
            second_model_route
            and _model_route_identity(second_model_route, current)
            == _model_route_identity(model_route, current)
        ):
            return False, {
                "ok": False,
                "error": (
                    "The second-opinion model must differ from the assigned "
                    "primary and resolve to a different provider/model identity."
                ),
            }
        adjudicator_identity = _model_route_identity(adjudicator_model_route, current)
        if adjudicator_model_route and adjudicator_identity in {
            _model_route_identity(model_route, current),
            _model_route_identity(second_model_route, current),
        }:
            return False, {
                "ok": False,
                "error": (
                    "The adjudicator must differ from both the primary and "
                    "second-opinion provider/model identities."
                ),
            }
        current["agent_models"][role] = model_route
        current["agent_second_opinion_models"][role] = second_model_route
        current["agent_adjudicator_models"][role] = adjudicator_model_route
        ok, normalized = normalize_soc_ai_settings(current)
        if not ok:
            return False, normalized
        saved, response = _write_soc_ai_settings(normalized)
        if saved:
            response["message"] = f"Model assignment saved for {role}."
            response["role"] = role
            response["model_route"] = normalized["agent_models"][role]
            response["second_opinion_model_route"] = normalized["agent_second_opinion_models"][role]
            response["adjudicator_model_route"] = normalized["agent_adjudicator_models"][role]
        return saved, response


def admin_status_path(action_id: str) -> Path:
    return ADMIN_STATE_DIR / f"{action_id}.json"


def admin_log_path(action_id: str) -> Path:
    return ADMIN_STATE_DIR / f"{action_id}.log"


def process_is_running(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def read_admin_action_status(action_id: str) -> dict:
    action = ADMIN_ACTIONS.get(action_id, {})
    current_command = " ".join(str(part) for part in action.get("command", []))
    status = {
        "id": action_id,
        "label": action.get("label", action_id),
        "summary": action.get("summary", ""),
        "command": current_command,
        "started_at": None,
        "pid": None,
        "state": "idle",
        "returncode": None,
        "message": "Not run yet.",
        "updated_at": None,
    }
    path = admin_status_path(action_id)
    loaded_has_command = False
    try:
        if path.exists():
            loaded_status = json.loads(path.read_text(encoding="utf-8"))
            loaded_has_command = "command" in loaded_status
            status.update(loaded_status)
    except Exception as exc:
        status.update({"state": "error", "message": f"Could not read status: {exc}"})
    if action_id == "reboot" and status.get("started_at") and ((not loaded_has_command) or status.get("command") != current_command):
        status.update({
            "command": current_command,
            "message": "Last reboot run was recorded before the current reboot command path changed; the timestamp is retained for audit history.",
        })
    if status.get("state") == "running" and not process_is_running(status.get("pid")):
        status["state"] = "unknown"
        status["message"] = "Process is no longer visible; check the log for completion details."
    return status


def write_admin_action_status(action_id: str, status: dict) -> None:
    ADMIN_STATE_DIR.mkdir(parents=True, exist_ok=True)
    status["updated_at"] = now_iso_local()
    admin_status_path(action_id).write_text(json.dumps(status, indent=2), encoding="utf-8")


def _parse_admin_status_time(value: object) -> dt.datetime | None:
    if not value:
        return None
    try:
        return parse_iso_timestamp(value)
    except Exception:
        return None


def latest_admin_action_outcome() -> dict | None:
    """Return the newest non-running admin action outcome for status banner rendering."""
    newest: dict | None = None
    newest_time: dt.datetime | None = None
    for action_id, action in ADMIN_ACTIONS.items():
        status = read_admin_action_status(action_id)
        state = str(status.get("state") or "idle")
        if state in {"idle", "running"}:
            continue
        when = (
            _parse_admin_status_time(status.get("finished_at"))
            or _parse_admin_status_time(status.get("updated_at"))
            or _parse_admin_status_time(status.get("started_at"))
        )
        if not when:
            continue
        if newest_time is None or when > newest_time:
            newest_time = when
            newest = {
                "id": action_id,
                "label": status.get("label") or action.get("label", action_id),
                "state": state,
                "returncode": status.get("returncode"),
                "message": status.get("message") or "No completion message recorded.",
                "when": format_iso_timestamp(when),
            }
    return newest


def read_admin_lock() -> dict | None:
    try:
        return json.loads(ADMIN_LOCK_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None


def running_admin_action() -> dict | None:
    """Return the currently running admin action, clearing stale locks when safe."""
    lock = read_admin_lock()
    if lock:
        pid = lock.get("pid")
        if process_is_running(pid):
            return lock
        try:
            ADMIN_LOCK_FILE.unlink()
        except FileNotFoundError:
            pass
        except Exception:
            return lock
    for action_id in ADMIN_ACTIONS:
        status = read_admin_action_status(action_id)
        if status.get("state") == "running" and process_is_running(status.get("pid")):
            return {
                "id": action_id,
                "label": status.get("label") or ADMIN_ACTIONS[action_id]["label"],
                "pid": status.get("pid"),
                "started_at": status.get("started_at"),
            }
    return None


def claim_admin_action_lock(action_id: str, label: str, started_at: str) -> tuple[bool, str]:
    """Atomically claim the singleton admin-action lock."""
    ADMIN_STATE_DIR.mkdir(parents=True, exist_ok=True)
    running = running_admin_action()
    if running:
        return False, f"{running.get('label', 'Another admin action')} is still running as PID {running.get('pid', 'unknown')}. Wait for it to complete before starting another update or reboot."
    payload = {"id": action_id, "label": label, "pid": None, "started_at": started_at}
    try:
        fd = os.open(str(ADMIN_LOCK_FILE), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        return True, "Lock acquired."
    except FileExistsError:
        running = running_admin_action()
        if running:
            return False, f"{running.get('label', 'Another admin action')} is still running as PID {running.get('pid', 'unknown')}. Wait for it to complete before starting another update or reboot."
        return claim_admin_action_lock(action_id, label, started_at)
    except Exception as exc:
        return False, f"Could not acquire admin action lock: {exc}"


def update_admin_action_lock_pid(action_id: str, pid: int) -> None:
    lock = read_admin_lock() or {}
    if lock.get("id") == action_id:
        lock["pid"] = pid
        ADMIN_LOCK_FILE.write_text(json.dumps(lock, indent=2), encoding="utf-8")


def release_admin_action_lock(action_id: str) -> None:
    lock = read_admin_lock() or {}
    if not lock or lock.get("id") == action_id:
        try:
            ADMIN_LOCK_FILE.unlink()
        except FileNotFoundError:
            pass


def start_admin_action(action_id: str, confirmation: str = "") -> tuple[bool, str]:
    action = ADMIN_ACTIONS.get(action_id)
    if not action:
        return False, "Unknown admin action."
    required = action.get("requires_confirmation")
    if required and confirmation != required:
        return False, f"Confirmation failed. Type {required!r} to run this action."
    running = running_admin_action()
    if running:
        return False, f"{running.get('label', 'Another admin action')} is still running as PID {running.get('pid', 'unknown')}. Wait for it to complete before starting another update or reboot."
    current = read_admin_action_status(action_id)
    if current.get("state") == "running" and process_is_running(current.get("pid")):
        return False, f"{action['label']} is already running."
    available, availability_message = check_admin_action_available(action_id)
    if not available:
        return False, availability_message
    ADMIN_STATE_DIR.mkdir(parents=True, exist_ok=True)
    log_path = admin_log_path(action_id)
    started_at = now_iso_local()
    lock_ok, lock_message = claim_admin_action_lock(action_id, str(action["label"]), started_at)
    if not lock_ok:
        return False, lock_message
    command = [str(part) for part in action["command"]]
    with log_path.open("ab") as log:
        log.write(f"\n===== {started_at} START {action['label']} =====\n".encode("utf-8"))
        log.write(("Command: " + " ".join(command) + "\n").encode("utf-8"))
        log.flush()
    initial_status = {
        "id": action_id,
        "label": action["label"],
        "summary": action.get("summary", ""),
        "command": " ".join(command),
        "started_at": started_at,
        "pid": None,
        "state": "running",
        "returncode": None,
        "message": f"Starting {action['label']}.",
    }
    write_admin_action_status(action_id, initial_status)
    status_path = admin_status_path(action_id)
    lock_path = ADMIN_LOCK_FILE
    finish_py = (
        "import datetime,json,pathlib,subprocess,sys; "
        f"p=pathlib.Path({str(status_path)!r}); "
        f"lp=pathlib.Path({str(lock_path)!r}); "
        f"aid={action_id!r}; "
        "d=json.loads(p.read_text()); "
        "rc=int(sys.argv[1]); "
        "label=d.get('label') or aid; "
        "d.update({'state':'ok' if rc == 0 else 'failed', 'returncode':rc, "
        "'message':(f'{label} completed successfully.' if rc == 0 else f'{label} failed with exit code {rc}.'), "
        "'finished_at':datetime.datetime.now().astimezone().isoformat(timespec='seconds').replace('T','  '), "
        "'updated_at':datetime.datetime.now().astimezone().isoformat(timespec='seconds').replace('T','  ')}); "
        "p.write_text(json.dumps(d, indent=2)); "
        f"checker=pathlib.Path({str(HOME / '.hermes' / 'scripts' / 'check_macos_updates.py')!r}); "
        "\ntry:\n subprocess.run([str(checker)], timeout=300) if (rc == 0 and aid == 'macos-update' and checker.exists()) else None\n"
        "except Exception: pass\n"
        "try:\n l=json.loads(lp.read_text()) if lp.exists() else {};\n"
        " lp.unlink() if (not l or l.get('id') == aid) else None\n"
        "except Exception: pass"
    )
    shell_command = " ".join(shlex.quote(part) for part in command)
    wrapped_command = (
        f"{shell_command}; rc=$?; "
        f"printf '\\n===== %s END {shlex.quote(action['label'])} rc=%s =====\\n' \"$(date -u '+%Y-%m-%d  %H:%M:%SZ')\" \"$rc\"; "
        f"/usr/bin/python3 -c {shlex.quote(finish_py)} \"$rc\"; exit $rc"
    )
    with log_path.open("ab") as log:
        try:
            proc = subprocess.Popen(
                ["/bin/bash", "-lc", wrapped_command],
                stdout=log,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                cwd=str(HOME),
                env=ADMIN_COMMAND_ENV,
                start_new_session=True,
            )
        except Exception as exc:
            release_admin_action_lock(action_id)
            write_admin_action_status(action_id, {
                **initial_status,
                "state": "failed",
                "returncode": None,
                "message": f"Failed to start {action['label']}: {exc}",
            })
            return False, f"Failed to start {action['label']}: {exc}"
    initial_status["pid"] = proc.pid
    initial_status["message"] = f"Started {action['label']} as PID {proc.pid}."
    update_admin_action_lock_pid(action_id, proc.pid)
    write_admin_action_status(action_id, initial_status)
    return True, f"Started {action['label']}."


def tail_file(path: Path, max_chars: int = 7000) -> str:
    try:
        data = path.read_bytes()
    except Exception:
        return "No log output yet."
    if len(data) > max_chars:
        data = data[-max_chars:]
    return data.decode("utf-8", errors="replace")


def _parse_cron_time(value: object) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = parse_iso_timestamp(value)
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        return parsed.astimezone()
    except Exception:
        return None


def _cron_failure_status(status: str) -> bool:
    status = status.lower().strip()
    if not status:
        return False
    return any(marker in status for marker in ("fail", "error", "timeout", "exception"))


def _cron_job_index() -> dict[str, dict]:
    try:
        data = json.loads(CRON_JOBS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    jobs: dict[str, dict] = {}
    for job in data.get("jobs", []):
        jid = str(job.get("id") or job.get("job_id") or "").strip()
        if jid:
            jobs[jid] = job
    return jobs


def cron_failure_records(limit: int = 12) -> list[dict]:
    """Collect recent failed Hermes cron runs from jobs.json and cron output files."""
    records: list[dict] = []
    seen: set[tuple[str, str]] = set()
    jobs = _cron_job_index()

    def add_record(job_id: str, name: str, status: str, when: dt.datetime | None, detail: str, source: Path | None) -> None:
        detail = redact_sensitive_text(detail.strip()) if detail else "No failure detail recorded."
        source_key = str(source) if source else str(when or "jobs.json")
        key = (job_id, source_key)
        if key in seen:
            return
        seen.add(key)
        records.append({
            "job_id": job_id or "unknown",
            "name": name or jobs.get(job_id, {}).get("name") or "Unnamed cron",
            "status": status or "error",
            "when": when,
            "detail": detail,
            "source": source,
        })

    # Output files preserve complete run-level failure logs, including tracebacks.
    try:
        output_files = sorted(
            [p for p in CRON_OUTPUT_DIR.rglob("*.md") if p.is_file()],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[:300]
    except Exception:
        output_files = []
    for path in output_files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        status_match = re.search(r"^\*\*Status:\*\*\s*(.+)$", text, re.MULTILINE)
        status = status_match.group(1).strip() if status_match else ""
        if not _cron_failure_status(status):
            continue
        name_match = re.search(r"^#\s+Cron Job:\s*(.+)$", text, re.MULTILINE)
        id_match = re.search(r"^\*\*Job ID:\*\*\s*(.+)$", text, re.MULTILINE)
        run_match = re.search(r"^\*\*Run Time:\*\*\s*(.+)$", text, re.MULTILINE)
        job_id = id_match.group(1).strip() if id_match else path.parent.name
        name = name_match.group(1).strip() if name_match else str(jobs.get(job_id, {}).get("name") or "Unnamed cron")
        when = _parse_cron_time(run_match.group(1).strip()) if run_match else dt.datetime.fromtimestamp(path.stat().st_mtime).astimezone()
        add_record(job_id, name, status, when, text, path)

    # jobs.json carries the latest error even when an output artifact is missing.
    for job_id, job in jobs.items():
        last_status = str(job.get("last_status") or "")
        last_error = str(job.get("last_error") or "")
        if not last_error and not _cron_failure_status(last_status):
            continue
        when = _parse_cron_time(job.get("last_run_at") or job.get("updated_at") or job.get("created_at"))
        if when and any(
            row.get("job_id") == job_id
            and isinstance(row.get("when"), dt.datetime)
            and abs((row["when"] - when).total_seconds()) <= 5
            for row in records
        ):
            continue
        detail = last_error or f"Last status: {last_status}"
        add_record(job_id, str(job.get("name") or "Unnamed cron"), last_status or "error", when, detail, None)

    records.sort(key=lambda row: row.get("when") or dt.datetime.fromtimestamp(0).astimezone(), reverse=True)
    return records[:limit]


def render_cron_failure_log_section() -> str:
    records = cron_failure_records()
    if not records:
        body = '<p>No failed Hermes cron runs found in <code>{}</code> or <code>{}</code>.</p>'.format(
            html.escape(str(CRON_JOBS_FILE)),
            html.escape(str(CRON_OUTPUT_DIR)),
        )
    else:
        table_rows = []
        detail_blocks = []
        for idx, row in enumerate(records, 1):
            when = row.get("when")
            when_label = format_iso_timestamp(when.astimezone()) if isinstance(when, dt.datetime) else "unknown time"
            source = row.get("source")
            source_label = str(source) if source else str(CRON_JOBS_FILE)
            detail = str(row.get("detail") or "No failure detail recorded.")
            if len(detail) > 9000:
                detail = detail[-9000:]
            table_rows.append(
                f"<tr><td>{idx}</td><td>{html.escape(str(row.get('name') or 'Unnamed cron'))}<br><code>{html.escape(str(row.get('job_id') or 'unknown'))}</code></td>"
                f"<td><span class=\"badge warn\">{html.escape(str(row.get('status') or 'error'))}</span></td>"
                f"<td>{html.escape(when_label)}</td><td><code>{html.escape(source_label)}</code></td></tr>"
            )
            detail_blocks.append(
                f"<details class=\"cron-failure-detail\" {'open' if idx == 1 else ''}>"
                f"<summary>{html.escape(str(row.get('name') or 'Unnamed cron'))} · {html.escape(str(row.get('status') or 'error'))} · {html.escape(when_label)}</summary>"
                f"<pre>{html.escape(detail)}</pre></details>"
            )
        body = f'''
<p>Recent failed Hermes cron runs from <code>{html.escape(str(CRON_JOBS_FILE))}</code> and <code>{html.escape(str(CRON_OUTPUT_DIR))}</code>.</p>
<table><thead><tr><th>#</th><th>Job</th><th>Status</th><th>Run time</th><th>Source</th></tr></thead><tbody>{''.join(table_rows)}</tbody></table>
{''.join(detail_blocks)}'''
    return f'<section class="section cron-failure-log"><h2>Cron failure log</h2>{body}</section>'



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


def _json_outdated_entries(data: dict) -> list[dict]:
    """Normalize Homebrew outdated --json=v2 formula/cask entries."""
    entries: list[dict] = []
    for section in ("formulae", "casks"):
        raw_items = data.get(section) if isinstance(data, dict) else []
        if not isinstance(raw_items, list):
            continue
        for item in raw_items:
            if isinstance(item, dict):
                copied = dict(item)
                copied["kind"] = "cask" if section == "casks" else "formula"
                entries.append(copied)
    return entries


def _brew_entry_versions(item: dict) -> tuple[str, str, str]:
    """Return name/current/latest display strings from a Homebrew JSON entry."""
    name = str(item.get("name") or item.get("token") or item.get("full_name") or "unknown")
    installed_raw = item.get("installed_versions") or item.get("installed_version") or item.get("installed") or []
    if isinstance(installed_raw, list):
        installed = ", ".join(str(x) for x in installed_raw if x) or "installed"
    else:
        installed = str(installed_raw or "installed")
    current_raw = item.get("current_version") or item.get("current_versions") or item.get("latest_version") or item.get("latest") or "available"
    if isinstance(current_raw, list):
        current = ", ".join(str(x) for x in current_raw if x) or "available"
    else:
        current = str(current_raw or "available")
    return name, installed, current


def _shorten(value: str, max_len: int = 96) -> str:
    value = " ".join(str(value).split())
    if len(value) <= max_len:
        return value
    return value[: max_len - 1].rstrip() + "…"


def admin_action_version_info(action_id: str) -> dict[str, str]:
    """Return current/latest version metadata for an Administration update card."""
    if action_id == "macos-update":
        _rc, sw = _run_admin_version_command(["/usr/bin/sw_vers"], timeout=6)
        fields: dict[str, str] = {}
        for line in sw.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key.strip()] = value.strip()
        version = fields.get("ProductVersion") or "Unknown"
        build = fields.get("BuildVersion")
        current = f"macOS {version}" + (f" ({build})" if build else "")
        data = read_macos_update_status()
        updates = data.get("updates") if isinstance(data.get("updates"), list) else []
        if updates:
            latest = _shorten(str(updates[0]), 120)
            detail = f"{len(updates)} cached macOS update(s) available from softwareupdate check at {data.get('checked_at') or 'unknown time'}."
        elif int(data.get("count", 0) or 0) == 0:
            latest = "Current"
            detail = f"No cached macOS updates available. Last checked {data.get('checked_at') or 'unknown time'}."
        else:
            latest = "Unknown"
            detail = f"macOS update availability is unknown. Last check: {data.get('status') or 'not checked'}."
        return {"current": current, "latest": latest, "detail": detail}

    if action_id == "brew-update":
        _rc, version_out = _run_admin_version_command(["/opt/homebrew/bin/brew", "--version"], timeout=8)
        current = version_out.splitlines()[0].strip() if version_out.splitlines() else "Homebrew version unknown"
        rc, outdated_out = _run_admin_version_command(["/opt/homebrew/bin/brew", "outdated", "--json=v2"], timeout=25)
        entries: list[dict] = []
        if rc == 0:
            try:
                json_start = outdated_out.find("{")
                payload = outdated_out[json_start:] if json_start >= 0 else outdated_out
                entries = _json_outdated_entries(json.loads(payload))
            except Exception:
                entries = []
        if entries:
            version_bits = []
            detail_bits = []
            for item in entries[:6]:
                name, installed, latest_version = _brew_entry_versions(item)
                version_bits.append(f"{name} {latest_version}")
                detail_bits.append(f"{name}: {installed} → {latest_version}")
            suffix = "" if len(entries) <= 6 else f" +{len(entries) - 6} more"
            latest = _shorten(", ".join(version_bits) + suffix, 140)
            detail = f"{len(entries)} Homebrew package(s) outdated: " + "; ".join(detail_bits) + ("." if len(entries) <= 6 else f"; plus {len(entries) - 6} more.")
        elif rc == 0:
            latest = "Current"
            detail = "No Homebrew formulae or casks are outdated."
        else:
            latest = "Unknown"
            detail = _shorten(outdated_out or "Could not determine Homebrew outdated versions.", 260)
        return {"current": current, "latest": latest, "detail": detail}

    if action_id == "hermes-update":
        _rc, version_out = _run_admin_version_command([HERMES_BIN, "--version"], timeout=25)
        current_line = version_out.splitlines()[0].strip() if version_out.splitlines() else "Hermes Agent version unknown"
        project = HOME / ".hermes" / "hermes-agent"
        _lrc, local_hash = _run_admin_version_command(["/usr/bin/git", "-C", str(project), "rev-parse", "--short", "HEAD"], timeout=8)
        _orc, origin_hash = _run_admin_version_command(["/usr/bin/git", "-C", str(project), "rev-parse", "--short", "origin/main"], timeout=8)
        _src, subject = _run_admin_version_command(["/usr/bin/git", "-C", str(project), "log", "origin/main", "-1", "--pretty=%s"], timeout=8)
        _vrc, origin_init = _run_admin_version_command(["/usr/bin/git", "-C", str(project), "show", "origin/main:hermes_cli/__init__.py"], timeout=8)
        version_match = re.search(r"Hermes Agent\s+(v\S+)", current_line)
        version_label = version_match.group(1) if version_match else current_line
        origin_version_match = re.search(r"__version__\s*=\s*['\"]([^'\"]+)['\"]", origin_init)
        origin_release_match = re.search(r"__release_date__\s*=\s*['\"]([^'\"]+)['\"]", origin_init)
        origin_version_label = f"v{origin_version_match.group(1)}" if origin_version_match else "latest"
        origin_release_label = f" ({origin_release_match.group(1)})" if origin_release_match else ""
        current = _shorten(f"Hermes Agent {version_label}" + (f" · {local_hash}" if local_hash else ""), 110)
        update_available = local_hash and origin_hash and local_hash != origin_hash
        if update_available:
            latest = _shorten(f"Hermes Agent {origin_version_label}{origin_release_label} · {origin_hash}", 110)
            detail = _shorten(f"Current Hermes version {version_label} at commit {local_hash}; latest available is Hermes Agent {origin_version_label}{origin_release_label} at {origin_hash}. {subject}", 260)
        elif "Update available" in version_out:
            latest = "Available"
            detail = _shorten("Hermes reports an update is available: " + " ".join(version_out.splitlines()[-2:]), 220)
        else:
            latest = "Current"
            detail = _shorten(f"Current commit {local_hash or 'unknown'} matches origin/main." if local_hash else "No Hermes update version detail available.", 220)
        return {"current": current, "latest": latest, "detail": detail}

    return {"current": "Not applicable", "latest": "Not applicable", "detail": "This action does not have update-version metadata."}

def check_admin_action_available(action_id: str, skip_expensive: bool = False) -> tuple[bool, str]:
    """Return whether an admin action can be started because relevant updates exist."""
    if action_id == "reboot":
        return True, "Reboot is available when no other admin action is running and typed confirmation is provided."
    if skip_expensive:
        return True, "Availability check skipped while another admin action is running."
    if action_id == "macos-update":
        data = read_macos_update_status()
        try:
            count = int(data.get("count", -1))
        except Exception:
            count = -1
        checked_at = str(data.get("checked_at") or "unknown time")
        if count > 0:
            return True, f"{count} macOS update(s) available. Last checked {checked_at}."
        if count == 0:
            return False, f"No macOS updates available. Last checked {checked_at}."
        return False, f"macOS update availability is unknown. Refresh the update check first. Last checked {checked_at}."
    if action_id == "brew-update":
        try:
            proc = subprocess.run(
                ["/opt/homebrew/bin/brew", "outdated", "--quiet"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                env=ADMIN_COMMAND_ENV,
            )
            outdated = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
            if outdated:
                preview = ", ".join(outdated[:5])
                suffix = "" if len(outdated) <= 5 else f" and {len(outdated) - 5} more"
                return True, f"{len(outdated)} Homebrew package(s) outdated: {preview}{suffix}."
            if proc.returncode == 0:
                return False, "No Homebrew updates available."
            return False, f"Could not determine Homebrew update availability: {proc.stderr.strip() or 'brew outdated failed'}."
        except Exception as exc:
            return False, f"Could not determine Homebrew update availability: {exc}"
    if action_id == "hermes-update":
        try:
            proc = subprocess.run(
                [HERMES_BIN, "update", "--check"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=45,
                env=ADMIN_COMMAND_ENV,
            )
            output = proc.stdout.strip()
            lower = output.lower()
            if "update available" in lower or "commit behind" in lower:
                return True, "Hermes Agent update is available."
            if "up to date" in lower or "already up" in lower or "no update" in lower:
                return False, "No Hermes Agent update available."
            if proc.returncode == 0:
                return False, f"No Hermes Agent update detected. Check output: {output[-240:] or 'empty output'}."
            return False, f"Could not determine Hermes Agent update availability: {output[-240:] or 'hermes update --check failed'}."
        except Exception as exc:
            return False, f"Could not determine Hermes Agent update availability: {exc}"
    return True, "No update availability rule is configured for this action."


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
    name_title = path.stem.replace("_", " ").strip()
    try:
        data = path.read_text(errors="ignore")[:20000]
        import re
        m = re.search(r"<title[^>]*>(.*?)</title>", data, flags=re.I | re.S)
        if m:
            t = html.unescape(re.sub(r"\s+", " ", m.group(1)).strip())
            if t:
                return t
        h = re.search(r"<h1[^>]*>(.*?)</h1>", data, flags=re.I | re.S)
        if h:
            t = html.unescape(re.sub(r"<[^>]+>", "", h.group(1))).strip()
            if t:
                return t
    except Exception:
        pass
    return name_title or path.name


def category_for(path: Path) -> str:
    sp = str(path)
    if "/report_portal/library/Threat Intel/" in sp or "Daily Threat Intel Briefs" in sp:
        return "Threat Intel"
    if "/report_portal/library/Threat Hunting/" in sp or "/ThreatHunting/ATHF/" in sp:
        return "Threat Hunting"
    if "/report_portal/library/Product Research/" in sp or "entrepreneurial_product_research_reports" in sp or "entrepreneurial_research" in sp:
        return "Product Research"
    if "/report_portal/library/Projects/" in sp:
        try:
            rel = path.relative_to(HOME / "report_portal" / "library" / "Projects")
            return f"Project: {rel.parts[0]}" if rel.parts else "Projects"
        except Exception:
            return "Projects"
    if "/gitProjects/" in sp:
        try:
            rel = path.relative_to(HOME / "gitProjects")
            return f"Project: {rel.parts[0]}" if rel.parts else "Projects"
        except Exception:
            return "Projects"
    if "/report_portal/library/Cybersecurity Library/" in sp or "Cybersecurity Library Web" in sp:
        return "Cybersecurity"
    if "/report_portal/library/Cybersecurity/" in sp or "Sigma Learning Web" in sp:
        return "Cybersecurity"
    if "/report_portal/library/Resource Library/" in sp or "Resource Library Web" in sp:
        return "Cybersecurity"
    if "/report_portal/library/Portal Operations/" in sp or "LAN Portal Web Server Architecture" in path.name:
        return "Portal Operations"
    if "/report_portal/library/Web App Projects/" in sp or "Web App Projects Web" in sp:
        return "Web App Projects"
    if "/report_portal/library/Prototype Web App/" in sp or "forest_room" in path.name.lower():
        return "Prototype: Web app"
    if "/report_portal/library/Local AI/" in sp or "Local LLM Benchmark Dashboard" in path.name:
        return "Local AI"
    return "Reports"


def should_skip_dir(path: Path) -> bool:
    return path.name in EXCLUDE_DIR_NAMES or path.name.startswith(".")


def report_id(path: Path) -> str:
    return hashlib.sha1(str(path).encode()).hexdigest()[:16]


def scan_reports() -> list[Report]:
    paths: list[Path] = []
    for root in SCAN_ROOTS:
        if not root.exists():
            continue
        if root.is_file() and root.suffix.lower() in (".html", ".htm"):
            paths.append(root)
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not should_skip_dir(Path(dirpath) / d)]
            for filename in filenames:
                if filename.lower().endswith((".html", ".htm")):
                    paths.append(Path(dirpath) / filename)
    for f in STANDALONE_HTML:
        if f.exists():
            paths.append(f)
    seen = set()
    reports = []
    for p in paths:
        try:
            p = p.resolve()
            if p in seen or not p.is_file():
                continue
            seen.add(p)
            st = p.stat()
            try:
                rel = str(p.relative_to(HOME))
            except Exception:
                rel = str(p)
            reports.append(Report(
                rid=report_id(p),
                title=title_from_html(p),
                path=p,
                rel=rel,
                category=category_for(p),
                size=st.st_size,
                mtime=st.st_mtime,
                is_index=p.name.lower() in ("index.html", "index.htm"),
            ))
        except Exception:
            continue
    return sorted(reports, key=lambda r: (r.mtime, r.title.lower()), reverse=True)


def soc_alerts_report(reports: list[Report]) -> Report | None:
    """Return the SOC Alerts dashboard report used as the LAN Portal default page."""
    return next((r for r in reports if r.title == "SOC Alerts" or "Cybersecurity/SOC Alerts/index.html" in r.rel), None)


def soc_alerts_default_path(reports: list[Report]) -> str | None:
    report = soc_alerts_report(reports)
    return f"/view/{report.rid}/" if report else None


def is_daily_threat_brief_file(report: Report) -> bool:
    """Return True for individual daily brief HTML files now grouped under the dashboard."""
    return (
        report.category == "Threat Intel"
        and not report.is_index
        and report.path.name.endswith(" - Daily Threat Intel Brief.html")
    )


def human_size(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} TB"


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


def process_matches(matchers: list[str], exclude: list[str] | None = None) -> list[str]:
    """Return ps output lines whose command text matches any supplied substring."""
    exclude = exclude or []
    proc = subprocess.run(
        ["/bin/ps", "axww", "-o", "pid=,args="],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3,
        check=True,
    )
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return [
        line for line in lines
        if any(matcher in line for matcher in matchers)
        and not any(blocked in line for blocked in exclude)
    ]


def macs_fan_control_status() -> tuple[bool, str]:
    """Return whether Macs Fan Control is currently running plus detail text."""
    try:
        matches = process_matches([
            "Macs Fan Control.app/Contents/MacOS/Macs Fan Control",
            "com.crystalidea.macsfancontrol",
            "MacsFanControl",
        ], exclude=["grep"])
        if matches:
            preview = " | ".join(matches[:2])
            return True, f"Macs Fan Control is running: {preview}"
        return False, "WARNING: Macs Fan Control is not currently running on this system."
    except Exception as exc:
        return False, f"WARNING: Unable to verify Macs Fan Control process state: {exc}"


def codex_app_status() -> tuple[bool, str]:
    """Return whether the Codex desktop app is currently running plus detail text."""
    try:
        matches = process_matches([
            "/Applications/Codex.app/Contents/MacOS/Codex",
            "/Applications/Codex.app/Contents/Resources/codex app-server",
        ], exclude=["grep"])
        if matches:
            preview = " | ".join(matches[:2])
            return True, f"Codex app is running: {preview}"
        return False, "WARNING: Codex app is not currently running on this system."
    except Exception as exc:
        return False, f"WARNING: Unable to verify Codex app process state: {exc}"


def codex_cli_status() -> tuple[bool, str]:
    """Return whether the Codex command-line interface is currently running."""
    try:
        proc = subprocess.run(
            ["/bin/ps", "axww", "-o", "pid=,args="],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
            check=True,
        )
        matches: list[str] = []
        exclude_bits = [
            "/Applications/Codex.app/",
            "Codex Computer Use.app/",
            "Codex for Chrome",
            "com.openai.codex",
            "Sparkle/Launcher",
            "browser_crashpad_handler",
            "grep",
        ]
        cli_patterns = [
            re.compile(r"(^|/)codex(\s|$)", re.IGNORECASE),
            re.compile(r"(^|\s)codex\s+(exec|run|login|resume|mcp|sandbox|apply|--)", re.IGNORECASE),
            re.compile(r"openai[-_]codex", re.IGNORECASE),
        ]
        for raw_line in proc.stdout.splitlines():
            line = raw_line.strip()
            if not line or any(bit in line for bit in exclude_bits):
                continue
            if any(pattern.search(line) for pattern in cli_patterns):
                matches.append(line)
        if matches:
            preview = " | ".join(matches[:3])
            suffix = "" if len(matches) <= 3 else f" | +{len(matches) - 3} more"
            return True, f"Codex CLI is running: {preview}{suffix}"
        return False, "Codex CLI is not currently running."
    except Exception as exc:
        return False, f"WARNING: Unable to verify Codex CLI process state: {exc}"


def docker_status() -> tuple[bool, str]:
    """Return whether Docker is currently running plus detail text."""
    docker_bin = shutil.which("docker") or "/usr/local/bin/docker"
    try:
        info_proc = subprocess.run(
            [docker_bin, "info", "--format", "{{.ServerVersion}}"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=4,
            check=False,
            env={**os.environ, "PATH": ADMIN_COMMAND_ENV.get("PATH", os.environ.get("PATH", ""))},
        )
        if info_proc.returncode == 0 and info_proc.stdout.strip():
            version = info_proc.stdout.strip().splitlines()[0]
            return True, f"Docker daemon is running. Server version: {version}."
        desktop_matches = process_matches([
            "/Applications/Docker.app/Contents/MacOS/Docker",
            "com.docker.backend",
            "com.docker.hyperkit",
            "com.docker.virtualization",
            "docker desktop",
        ], exclude=["grep"])
        if desktop_matches:
            preview = " | ".join(desktop_matches[:2])
            return True, f"Docker Desktop process is running, but docker info did not return daemon details: {preview}"
        helper_matches = process_matches(["com.docker.vmnetd"], exclude=["grep"])
        helper_note = ""
        if helper_matches:
            helper_note = f" Docker helper is present but the daemon is unavailable: {' | '.join(helper_matches[:1])}."
        stderr = (info_proc.stderr or "").strip().splitlines()
        reason = stderr[-1] if stderr else "docker info did not report a running daemon"
        return False, f"WARNING: Docker is not currently running or the daemon is unavailable: {reason}.{helper_note}"
    except Exception as exc:
        return False, f"WARNING: Unable to verify Docker state: {exc}"


def n8n_container_status() -> dict[str, object]:
    """Return compact n8n container/app health without exposing container config."""
    now = dt.datetime.now().astimezone()
    checked_at = format_iso_timestamp(now)
    checked_label = format_iso_timestamp(now)
    docker_bin = shutil.which("docker") or "/usr/local/bin/docker"
    env = {**os.environ, "PATH": ADMIN_COMMAND_ENV.get("PATH", os.environ.get("PATH", ""))}
    base: dict[str, object] = {
        "id": "n8n",
        "label": "n8n container",
        "startable": False,
        "checked_at": checked_at,
    }
    try:
        inspect_proc = subprocess.run(
            [docker_bin, "inspect", N8N_CONTAINER_NAME],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
            env=env,
        )
    except Exception as exc:
        return {
            **base,
            "running": False,
            "level": "alert",
            "value": "Docker unavailable",
            "detail": f"WARNING: unable to inspect {N8N_CONTAINER_NAME}: {exc} · checked {checked_label}",
        }
    if inspect_proc.returncode != 0:
        stderr = (inspect_proc.stderr or inspect_proc.stdout or "docker inspect failed").strip().splitlines()
        reason = stderr[-1] if stderr else "docker inspect failed"
        lower_reason = reason.lower()
        value = "Missing" if "no such object" in lower_reason or "no such container" in lower_reason else "Docker unavailable"
        return {
            **base,
            "running": False,
            "level": "alert",
            "value": value,
            "detail": f"WARNING: {N8N_CONTAINER_NAME} status unavailable: {reason} · healthz not checked · checked {checked_label}",
        }
    try:
        inspect_data = json.loads(inspect_proc.stdout)
        container = inspect_data[0] if isinstance(inspect_data, list) and inspect_data else {}
    except Exception as exc:
        return {
            **base,
            "running": False,
            "level": "alert",
            "value": "Unknown",
            "detail": f"WARNING: unable to parse docker inspect output for {N8N_CONTAINER_NAME}: {exc} · checked {checked_label}",
        }
    state_obj = (container.get("State") or {}) if isinstance(container, dict) else {}
    host_config = (container.get("HostConfig") or {}) if isinstance(container, dict) else {}
    restart_obj = host_config.get("RestartPolicy") or {}
    state = str(state_obj.get("Status") or "unknown")
    started_at = str(state_obj.get("StartedAt") or "unknown")
    restart_policy = str(restart_obj.get("Name") or "none")
    health_ok = False
    health_detail = "not checked"
    if state == "running":
        try:
            health_proc = subprocess.run(
                ["/usr/bin/curl", "-fsS", "--max-time", "5", N8N_HEALTH_URL],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=7,
                check=False,
            )
            body = health_proc.stdout.strip()
            if health_proc.returncode == 0:
                try:
                    payload = json.loads(body)
                    health_ok = payload.get("status") == "ok"
                except Exception:
                    health_ok = body == '{"status":"ok"}'
                health_detail = "ok" if health_ok else f"unexpected response: {body[:120] or 'empty body'}"
            else:
                err = (health_proc.stderr or body or "curl failed").strip().splitlines()
                health_detail = err[-1] if err else "curl failed"
        except Exception as exc:
            health_detail = f"health check error: {exc}"
    if state != "running":
        level = "alert"
        value = state if state != "unknown" else "Unknown"
    elif not health_ok:
        level = "warn"
        value = "Health warning"
    elif restart_policy != "unless-stopped":
        level = "warn"
        value = "Policy warning"
    else:
        level = "ok"
        value = "Healthy"
    detail = (
        f"state={state} · healthz={health_detail} · restart={restart_policy} "
        f"· started={started_at} · checked {checked_label}"
    )
    return {
        **base,
        "running": level == "ok",
        "level": level,
        "value": value,
        "detail": detail,
        "container_state": state,
        "healthz": health_detail,
        "restart_policy": restart_policy,
        "started_at": started_at,
    }


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
    statuses: dict[str, dict[str, object]] = {}
    for service_id, checker in checks.items():
        running, detail = checker()
        statuses[service_id] = {
            "id": service_id,
            "label": ADMIN_SERVICE_LABELS[service_id],
            "running": running,
            "level": "ok" if running else "warn",
            "startable": True,
            "value": "Running" if running else "Not running",
            "detail": detail,
        }
    statuses["n8n"] = n8n_container_status()
    return statuses


def start_admin_service(service_id: str) -> tuple[bool, str, dict[str, object] | None]:
    """Start one allowed Administration service/app without repeating the request on refresh."""
    start_commands = {
        "macs-fan-control": ["/usr/bin/open", "-a", "Macs Fan Control"],
        "codex": ["/usr/bin/open", "-a", "Codex"],
        "codex-cli": ["/usr/bin/osascript", "-e", f'tell application "Terminal" to do script "{CODEX_CLI_BIN}"', "-e", 'tell application "Terminal" to activate'],
        "docker": ["/usr/bin/open", "-a", "Docker"],
    }
    if service_id not in start_commands:
        return False, "Unknown service.", None
    status = admin_service_statuses().get(service_id)
    if status and status.get("running"):
        return True, f"{ADMIN_SERVICE_LABELS[service_id]} is already running.", status
    try:
        subprocess.Popen(
            start_commands[service_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        status = admin_service_statuses().get(service_id)
        return True, f"Started {ADMIN_SERVICE_LABELS[service_id]}. The card will update when it reports running.", status
    except Exception as exc:
        status = admin_service_statuses().get(service_id)
        return False, f"Unable to start {ADMIN_SERVICE_LABELS[service_id]}: {exc}", status


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
    try:
        usage = shutil.disk_usage(HOME)
        percent_free = (usage.free / usage.total * 100) if usage.total else 0.0
        return int(usage.free), int(usage.total), percent_free
    except Exception:
        return 0, 0, 0.0


DISK_INVENTORY_CACHE: dict[str, object] = {"generated": 0.0, "dirs": [], "files": [], "warnings": []}


def _parse_size_path_lines(output: str, multiplier: int = 1) -> list[dict]:
    rows: list[dict] = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        try:
            size = int(parts[0]) * multiplier
        except Exception:
            continue
        rows.append({"size": size, "path": parts[1]})
    return rows


def _parse_file_stat_lines(output: str) -> list[dict]:
    rows: list[dict] = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(None, 2)
        if len(parts) != 3:
            continue
        try:
            allocated = int(parts[0]) * 512
            logical = int(parts[1])
        except Exception:
            continue
        rows.append({"size": allocated, "logical_size": logical, "path": parts[2]})
    return rows


def local_disk_inventory(limit: int = 10, cache_seconds: int = 600) -> tuple[list[dict], list[dict], list[str], dt.datetime]:
    """Return cached largest directories/files under HOME for the Local Disk detail page."""
    now = dt.datetime.now().astimezone()
    cached_at = float(DISK_INVENTORY_CACHE.get("generated") or 0.0)
    if cached_at and (now.timestamp() - cached_at) < cache_seconds:
        generated = dt.datetime.fromtimestamp(cached_at).astimezone()
        return (
            list(DISK_INVENTORY_CACHE.get("dirs") or []),
            list(DISK_INVENTORY_CACHE.get("files") or []),
            list(DISK_INVENTORY_CACHE.get("warnings") or []),
            generated,
        )

    warnings: list[str] = []
    top_dirs: list[dict] = []
    top_files: list[dict] = []
    try:
        proc = subprocess.run(
            ["/usr/bin/du", "-k", "-x", "-d", "4", str(HOME)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        dir_rows = [row for row in _parse_size_path_lines(proc.stdout, 1024) if row["path"] != str(HOME)]
        top_dirs = sorted(dir_rows, key=lambda row: row["size"], reverse=True)[:limit]
        if proc.stderr.strip():
            warnings.append("Directory scan warnings: " + proc.stderr.strip().splitlines()[-1])
    except subprocess.TimeoutExpired:
        warnings.append("Directory scan timed out after 30 seconds; showing cached/empty directory data.")
    except Exception as exc:
        warnings.append(f"Directory scan failed: {exc}")

    try:
        find_cmd = (
            f"/usr/bin/find {shlex.quote(str(HOME))} -xdev -type f -size +1M "
            "-exec /usr/bin/stat -f '%b\t%z\t%N' {} + 2>/dev/null "
            "| /usr/bin/sort -nr | /usr/bin/head -10"
        )
        proc = subprocess.run(
            ["/bin/bash", "-lc", find_cmd],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        top_files = _parse_file_stat_lines(proc.stdout)[:limit]
        if proc.stderr.strip():
            warnings.append("File scan warnings: " + proc.stderr.strip().splitlines()[-1])
    except subprocess.TimeoutExpired:
        warnings.append("File scan timed out after 30 seconds; showing cached/empty file data.")
    except Exception as exc:
        warnings.append(f"File scan failed: {exc}")

    DISK_INVENTORY_CACHE.update({
        "generated": now.timestamp(),
        "dirs": top_dirs,
        "files": top_files,
        "warnings": warnings,
    })
    return top_dirs, top_files, warnings, now


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


def latest_hermes_backup_metric() -> tuple[str, str, bool]:
    """Return display value, detail text, and warning state for successful Hermes DR backups.

    A successful backup requires a complete backup set plus confirmation from the
    scheduled backup log. Incomplete/newer artifacts are ignored for the displayed
    timestamp and surfaced as warnings instead.
    """
    log_file = HERMES_DR_BACKUP_DIR / "backup-cron.log"

    def backup_base(path: Path) -> Path:
        raw = str(path)
        if raw.endswith(".tar.zst.enc"):
            return Path(raw.removesuffix(".tar.zst.enc"))
        return Path(raw.removesuffix(".tar.zst"))

    def backup_dt(path: Path) -> dt.datetime:
        stem = path.name
        if stem.endswith(".tar.zst.enc"):
            marker = stem.removeprefix("macstudio-hermes-dr_").removesuffix(".tar.zst.enc")
        else:
            marker = stem.removeprefix("macstudio-hermes-dr_").removesuffix(".tar.zst")
        try:
            return dt.datetime.strptime(marker, "%Y%m%d_%H%M%SZ").replace(tzinfo=dt.timezone.utc)
        except Exception:
            return dt.datetime.fromtimestamp(path.stat().st_mtime, tz=dt.timezone.utc)

    try:
        artifacts = sorted(
            [*HERMES_DR_BACKUP_DIR.glob("macstudio-hermes-dr_*.tar.zst"), *HERMES_DR_BACKUP_DIR.glob("macstudio-hermes-dr_*.tar.zst.enc")],
            key=backup_dt,
        )
    except Exception:
        artifacts = []

    completed_archives: set[str] = set()
    non_dry_starts: list[dt.datetime] = []
    scheduled_completions: list[dt.datetime] = []
    log_warning = ""
    try:
        log_text = log_file.read_text(encoding="utf-8", errors="replace")
        completed_archives = set(re.findall(r"^Archive: (.*macstudio-hermes-dr_\d{8}_\d{6}Z\.tar\.zst(?:\.enc)?)$", log_text, re.MULTILINE))
        for stamp, dry_run in re.findall(r"^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\] Scheduled backup start: dry_run=(\d)", log_text, re.MULTILINE):
            if dry_run == "0":
                non_dry_starts.append(dt.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc))
        for stamp in re.findall(r"^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\] Scheduled backup complete\.", log_text, re.MULTILINE):
            scheduled_completions.append(dt.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc))
    except Exception as exc:
        log_warning = f"Could not read backup log {log_file}: {exc}"

    complete_sets: list[Path] = []
    incomplete_sets: list[str] = []
    for archive in artifacts:
        base = backup_base(archive)
        missing = []
        if not archive.with_suffix(archive.suffix + ".sha256").exists():
            missing.append("checksum")
        if not Path(str(base) + ".RESTORE.txt").exists():
            missing.append("restore notes")
        try:
            if archive.stat().st_size <= 0:
                missing.append("non-empty archive")
        except Exception:
            missing.append("readable archive")
        if completed_archives and str(archive) not in completed_archives:
            missing.append("success log entry")
        if missing:
            incomplete_sets.append(f"{archive.name} missing {', '.join(missing)}")
        else:
            complete_sets.append(archive)

    if not complete_sets:
        warning = True
        detail_bits = [f"WARNING: No successful full Hermes backup sets found in {HERMES_DR_BACKUP_DIR}"]
        if incomplete_sets:
            detail_bits.append("Incomplete artifacts: " + "; ".join(incomplete_sets[-3:]))
        if log_warning:
            detail_bits.append(log_warning)
        return "⚠ None", " · ".join(detail_bits), warning

    newest_success = max(complete_sets, key=backup_dt)
    timestamp = backup_dt(newest_success).astimezone()
    last_success_utc = backup_dt(newest_success)
    warnings: list[str] = []

    if incomplete_sets:
        newest_artifact = max(artifacts, key=backup_dt) if artifacts else None
        if newest_artifact and backup_dt(newest_artifact) > last_success_utc:
            warnings.append("Newer backup artifact is incomplete/not confirmed successful: " + incomplete_sets[-1])
    if non_dry_starts:
        latest_start = max(non_dry_starts)
        latest_complete = max(scheduled_completions) if scheduled_completions else None
        if latest_start > last_success_utc and (latest_complete is None or latest_complete < latest_start):
            warnings.append(f"Latest scheduled backup attempt started {format_iso_timestamp(latest_start.astimezone())} but did not log a successful completion")
    if log_warning:
        warnings.append(log_warning)

    warning = bool(warnings)
    value = ("⚠ " if warning else "") + relative_time_label(timestamp.timestamp())
    detail_bits = [
        f"Latest successful full Hermes backup: {newest_success.name}",
        format_iso_timestamp(timestamp.astimezone()),
        human_size(newest_success.stat().st_size),
        "success confirmed by backup-cron.log",
    ]
    if warnings:
        detail_bits.insert(0, "WARNING: " + " | ".join(warnings))
    return value, " · ".join(detail_bits), warning


def macos_update_metric() -> tuple[str, str, int]:
    """Return display value, tooltip/detail text, and update count for cached macOS update status."""
    try:
        data = json.loads(MACOS_UPDATE_STATUS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return "Not checked", "macOS update status has not been checked yet.", -1
    status = str(data.get("status") or "Unknown")
    checked_at = str(data.get("checked_at") or "unknown time")
    updates = data.get("updates") or []
    try:
        count = int(data.get("count", -1))
    except Exception:
        count = -1
    detail_bits = [f"Checked {checked_at}"]
    if isinstance(updates, list) and updates:
        detail_bits.append("Updates: " + "; ".join(str(x) for x in updates[:5]))
    if data.get("error"):
        detail_bits.append("Error: " + str(data.get("error")))
    return status, " · ".join(detail_bits), count


def brew_update_source_metric() -> tuple[int, str, list[str]]:
    """Return Homebrew outdated count, detail, and package names."""
    try:
        proc = subprocess.run(
            ["/opt/homebrew/bin/brew", "outdated", "--quiet"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=12,
            env=ADMIN_COMMAND_ENV,
        )
        outdated = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        if outdated:
            preview = ", ".join(outdated[:8])
            suffix = "" if len(outdated) <= 8 else f" and {len(outdated) - 8} more"
            return len(outdated), f"{len(outdated)} Homebrew package(s) outdated: {preview}{suffix}.", outdated
        if proc.returncode == 0:
            return 0, "No Homebrew updates available.", []
        return -1, f"Could not determine Homebrew updates: {proc.stderr.strip() or 'brew outdated failed'}.", []
    except Exception as exc:
        return -1, f"Could not determine Homebrew updates: {exc}", []


def hermes_update_source_metric() -> tuple[bool, str]:
    """Return whether Hermes Agent has an available update plus detail text."""
    try:
        proc = subprocess.run(
            [HERMES_BIN, "update", "--check"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
            env=ADMIN_COMMAND_ENV,
        )
        output = proc.stdout.strip()
        lower = output.lower()
        if "update available" in lower or "commits behind" in lower or "run 'hermes update'" in lower:
            first_line = output.splitlines()[0] if output.splitlines() else "Hermes Agent update is available."
            return True, f"Hermes Agent update available: {first_line}"
        if "up to date" in lower or "already up" in lower or "no update" in lower or proc.returncode == 0:
            return False, "No Hermes Agent update available."
        return False, f"Could not determine Hermes Agent update availability: {output[-240:] or 'hermes update --check failed'}."
    except Exception as exc:
        return False, f"Could not determine Hermes Agent update availability: {exc}"


def latest_running_update_action() -> tuple[str, str] | None:
    """Return currently running update action for the homepage Updates metric."""
    for action_id in ("macos-update", "brew-update", "hermes-update"):
        status = read_admin_action_status(action_id)
        if status.get("state") != "running":
            continue
        pid = status.get("pid")
        if not process_is_running(pid):
            continue
        action = ADMIN_ACTIONS.get(action_id, {})
        label = str(status.get("label") or action.get("label") or action_id)
        timestamp = status.get("started_at") or status.get("updated_at")
        try:
            parsed = parse_iso_timestamp(timestamp).astimezone() if timestamp else None
        except Exception:
            parsed = None
        exact = format_iso_timestamp(parsed) if parsed else "unknown time"
        short = "Update running"
        if "Homebrew" in label:
            short = "brew running"
        elif "macOS" in label:
            short = "macOS running"
        elif "Hermes" in label:
            short = "Hermes running"
        return short, f"{label} is currently running as PID {pid or 'unknown'}; started at {exact}. The Updates metric will refresh availability after the action completes."
    return None


def latest_update_action_failure() -> tuple[str, str] | None:
    """Return latest failed/unknown update action for the homepage warning metric."""
    failures: list[tuple[dt.datetime, str, str]] = []
    for action_id in ("macos-update", "brew-update", "hermes-update"):
        status = read_admin_action_status(action_id)
        state = str(status.get("state") or "idle")
        if state not in {"failed", "error", "unknown"}:
            continue
        timestamp = status.get("finished_at") or status.get("updated_at") or status.get("started_at")
        try:
            parsed = parse_iso_timestamp(timestamp).astimezone() if timestamp else dt.datetime.fromtimestamp(0).astimezone()
        except Exception:
            parsed = dt.datetime.fromtimestamp(0).astimezone()
        action = ADMIN_ACTIONS.get(action_id, {})
        label = str(action.get("label") or action_id)
        exact = format_iso_timestamp(parsed) if timestamp else "unknown time"
        message = str(status.get("message") or "No failure message recorded.")
        failures.append((parsed, label, f"WARNING: {label} last failed at {exact}. {message}"))
    if not failures:
        return None
    _parsed, label, detail = max(failures, key=lambda item: item[0])
    short = "Failed"
    if "Homebrew" in label:
        short = "brew failed"
    elif "macOS" in label:
        short = "macOS failed"
    elif "Hermes" in label:
        short = "Hermes failed"
    return short, detail


def prioritized_updates_metric() -> tuple[str, str, int, str]:
    """Return homepage Updates metric using priority: running update > failure > macOS > Homebrew > Hermes."""
    running = latest_running_update_action()
    if running:
        label, detail = running
        return f"⏳ {label}", detail, 2, "running"

    failure = latest_update_action_failure()
    if failure:
        label, detail = failure
        return f"⚠ {label}", detail, -2, "failed"

    _mac_value, mac_detail, mac_count = macos_update_metric()
    detail_parts = ["Priority order: macOS > Homebrew > Hermes Agent.", f"macOS: {mac_detail}"]
    if mac_count > 0:
        return f"{mac_count} macOS", " · ".join(detail_parts), mac_count, "macos"

    brew_count, brew_detail, _brew_items = brew_update_source_metric()
    detail_parts.append(f"Homebrew: {brew_detail}")
    if brew_count > 0:
        return f"{brew_count} brew", " · ".join(detail_parts), brew_count, "brew"

    hermes_available, hermes_detail = hermes_update_source_metric()
    detail_parts.append(f"Hermes: {hermes_detail}")
    if hermes_available:
        return "Hermes", " · ".join(detail_parts), 1, "hermes"

    if mac_count < 0 or brew_count < 0:
        return "Unknown", " · ".join(detail_parts), -1, "unknown"
    return "Current", " · ".join(detail_parts), 0, "none"


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
    try:
        data = json.loads(MACOS_UPDATE_STATUS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        return {"status": "Not checked", "count": -1, "updates": [], "error": str(exc)}


def backup_base_path(path: Path) -> Path:
    raw = str(path)
    if raw.endswith(".tar.zst.enc"):
        return Path(raw.removesuffix(".tar.zst.enc"))
    return Path(raw.removesuffix(".tar.zst"))


def backup_timestamp_from_name(path: Path) -> dt.datetime:
    stem = path.name
    if stem.endswith(".tar.zst.enc"):
        marker = stem.removeprefix("macstudio-hermes-dr_").removesuffix(".tar.zst.enc")
    else:
        marker = stem.removeprefix("macstudio-hermes-dr_").removesuffix(".tar.zst")
    try:
        return dt.datetime.strptime(marker, "%Y%m%d_%H%M%SZ").replace(tzinfo=dt.timezone.utc)
    except Exception:
        return dt.datetime.fromtimestamp(path.stat().st_mtime, tz=dt.timezone.utc)


def backup_inventory() -> tuple[list[dict], dict]:
    log_file = HERMES_DR_BACKUP_DIR / "backup-cron.log"
    completed_archives: set[str] = set()
    log_text = ""
    try:
        log_text = log_file.read_text(encoding="utf-8", errors="replace")
        completed_archives = set(re.findall(r"^Archive: (.*macstudio-hermes-dr_\d{8}_\d{6}Z\.tar\.zst(?:\.enc)?)$", log_text, re.MULTILINE))
    except Exception:
        pass
    try:
        archives = sorted([*HERMES_DR_BACKUP_DIR.glob("macstudio-hermes-dr_*.tar.zst"), *HERMES_DR_BACKUP_DIR.glob("macstudio-hermes-dr_*.tar.zst.enc")], key=backup_timestamp_from_name, reverse=True)
    except Exception:
        archives = []
    rows = []
    for archive in archives:
        base = backup_base_path(archive)
        checksum = archive.with_suffix(archive.suffix + ".sha256")
        restore = Path(str(base) + ".RESTORE.txt")
        missing = []
        if not checksum.exists():
            missing.append("checksum")
        if not restore.exists():
            missing.append("restore notes")
        try:
            size = archive.stat().st_size
            if size <= 0:
                missing.append("non-empty archive")
        except Exception:
            size = 0
            missing.append("readable archive")
        if completed_archives and str(archive) not in completed_archives:
            missing.append("success log entry")
        created = backup_timestamp_from_name(archive).astimezone()
        ok = not missing
        rows.append({
            "archive": archive,
            "checksum": checksum,
            "restore": restore,
            "created": created,
            "size": size,
            "ok": ok,
            "rating": "Successful" if ok else "Needs attention",
            "missing": missing,
        })
    successful = sum(1 for row in rows if row["ok"])
    total = len(rows)
    meta = {
        "directory": HERMES_DR_BACKUP_DIR,
        "remote_dest": HERMES_DR_REMOTE_DEST,
        "remote_directory": HERMES_DR_REMOTE_DIR,
        "remote_location": f"{HERMES_DR_REMOTE_DEST}:{HERMES_DR_REMOTE_DIR}",
        "log_file": log_file,
        "total": total,
        "successful": successful,
        "rating_percent": round((successful / total * 100), 1) if total else 0.0,
        "log_tail": redact_sensitive_text("\n".join(log_text.splitlines()[-40:])) if log_text else "",
    }
    return rows, meta


def metric_detail_shell(title: str, kicker: str, body_html: str, hero_extra_html: str = "") -> bytes:
    page = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} · Mac Studio LAN Portal</title>
<style>
:root {{ --bg:#070b12; --panel:#111827; --panel2:#0b1220; --line:rgba(148,163,184,.18); --text:#edf5ff; --muted:#94a3b8; --cyan:#23d3ee; --green:#28e0a6; --blue:#4f8cff; --amber:#f8c76a; --pink:#ff7a90; --purple:#a78bfa; }}
* {{ box-sizing:border-box }}
body {{ margin:0; color:var(--text); font-family:Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:radial-gradient(circle at top left, rgba(35,211,238,.14), transparent 36%), linear-gradient(180deg, #07101c, #05070d 70%); }}
a {{ color:inherit }}
.shell {{ width:min(100% - 36px, 1180px); margin:0 auto; padding:28px 0 56px }}
.back {{ display:inline-flex; align-items:center; gap:8px; color:#aeeeff; text-decoration:none; border:1px solid var(--line); background:rgba(255,255,255,.035); border-radius:999px; padding:9px 12px; font-size:13px; font-weight:800 }}
.hero {{ margin:18px 0 18px; padding:24px; border:1px solid var(--line); border-radius:26px; background:linear-gradient(145deg, rgba(18,26,41,.96), rgba(10,15,25,.92)); box-shadow:0 18px 50px rgba(0,0,0,.22) }}
.hero-top {{ display:flex; align-items:flex-start; justify-content:space-between; gap:16px }}
.hero-main {{ min-width:0 }}
.hero-extra {{ flex:0 0 auto }}
.kicker {{ color:var(--cyan); font-size:12px; letter-spacing:.16em; text-transform:uppercase; font-weight:900 }}
h1 {{ margin:10px 0 0; font-size:clamp(32px, 5vw, 58px); line-height:.98; letter-spacing:-.055em }}
.grid {{ display:grid; grid-template-columns:repeat(3, minmax(0,1fr)); gap:14px; margin:18px 0 }}
.card,.section {{ border:1px solid var(--line); border-radius:22px; background:linear-gradient(145deg, rgba(18,26,41,.94), rgba(10,16,27,.90)); padding:18px; box-shadow:0 14px 40px rgba(0,0,0,.18); min-width:0 }}
.card span,.section-label {{ display:block; color:#9bdff2; font-size:11px; letter-spacing:.13em; text-transform:uppercase; font-weight:950; margin-bottom:8px }}
.card strong {{ display:block; font-size:clamp(22px, 3vw, 34px); letter-spacing:-.05em }}
.section {{ margin-top:14px }}
h2 {{ margin:0 0 14px; font-size:21px; letter-spacing:-.025em }}
p {{ color:#b7c4d8; line-height:1.55 }}
table {{ width:100%; border-collapse:collapse; overflow:hidden; border-radius:16px }}
th,td {{ text-align:left; border-bottom:1px solid rgba(148,163,184,.14); padding:11px 10px; vertical-align:top; font-size:13px }}
th {{ color:#dceaff; background:rgba(255,255,255,.045); font-size:11px; letter-spacing:.1em; text-transform:uppercase }}
td {{ color:#c8d6ea }}
code,pre {{ font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace }}
code {{ color:#aeeeff; overflow-wrap:anywhere }}
pre {{ white-space:pre-wrap; overflow:auto; color:#c8d6ea; background:#020403; border:1px solid rgba(148,163,184,.16); border-radius:18px; padding:14px; max-height:420px }}
.badge {{ display:inline-flex; align-items:center; border-radius:999px; padding:5px 8px; font-size:11px; font-weight:950; letter-spacing:.08em; text-transform:uppercase; border:1px solid rgba(40,224,166,.24); color:#a8f1dc; background:rgba(40,224,166,.07) }}
.badge.warn {{ border-color:rgba(248,199,106,.30); color:#ffd991; background:rgba(248,199,106,.08) }}
@media (max-width:800px) {{ .grid {{ grid-template-columns:1fr }} .shell {{ width:min(100% - 22px, 1180px); padding-top:18px }} .hero-top {{ flex-direction:column }} th,td {{ display:block; width:100% }} tr {{ display:block; border-bottom:1px solid rgba(148,163,184,.18); padding:8px 0 }} }}
</style>
</head>
<body><div class="shell"><a class="back" href="/">← Back to Mac Studio LAN Portal</a><section class="hero"><div class="hero-top"><div class="hero-main"><div class="kicker">{html.escape(kicker)}</div><h1>{html.escape(title)}</h1></div>{f'<div class="hero-extra">{hero_extra_html}</div>' if hero_extra_html else ''}</div></section>{body_html}</div></body></html>'''
    return page.encode("utf-8")


def render_macos_updates_detail() -> bytes:
    data = read_macos_update_status()
    status = str(data.get("status") or "Unknown")
    count = data.get("count", "Unknown")
    checked_at = str(data.get("checked_at") or "Not checked")
    ok = data.get("ok")
    updates = data.get("updates") if isinstance(data.get("updates"), list) else []
    update_rows = "".join(f"<tr><td>{idx}</td><td>{html.escape(str(item))}</td></tr>" for idx, item in enumerate(updates, 1)) or '<tr><td colspan="2">No cached update labels available.</td></tr>'
    raw_tail = html.escape(str(data.get("raw_tail") or "No raw softwareupdate output cached."))
    error = html.escape(str(data.get("error") or "None"))
    body = f'''
<section class="grid">
  <div class="card"><span>Status</span><strong>{html.escape(status)}</strong></div>
  <div class="card"><span>Available updates</span><strong>{html.escape(str(count))}</strong></div>
  <div class="card"><span>Last checked</span><strong>{html.escape(checked_at)}</strong></div>
</section>
<section class="section"><h2>Available update detail</h2><table><thead><tr><th>#</th><th>Update label</th></tr></thead><tbody>{update_rows}</tbody></table></section>
<section class="section"><h2>Check metadata</h2><table><tbody>
<tr><th>Cache file</th><td><code>{html.escape(str(MACOS_UPDATE_STATUS_FILE))}</code></td></tr>
<tr><th>Command</th><td><code>{html.escape(str(data.get('command') or '/usr/sbin/softwareupdate --list'))}</code></td></tr>
<tr><th>OK</th><td>{html.escape(str(ok))}</td></tr>
<tr><th>Return code</th><td>{html.escape(str(data.get('returncode', 'Unknown')))}</td></tr>
<tr><th>Error</th><td>{error}</td></tr>
</tbody></table></section>
<section class="section"><h2>Raw cached softwareupdate output tail</h2><pre>{raw_tail}</pre></section>'''
    return metric_detail_shell("macOS Updates", "Metric detail", body)


def render_prioritized_updates_detail() -> bytes:
    value, detail, count, source = prioritized_updates_metric()
    mac_value, mac_detail, mac_count = macos_update_metric()
    brew_count, brew_detail, brew_items = brew_update_source_metric()
    hermes_available, hermes_detail = hermes_update_source_metric()
    selected = {
        "macos": "macOS updates",
        "brew": "Homebrew updates",
        "hermes": "Hermes Agent updates",
        "none": "No updates available",
        "unknown": "Unknown update state",
        "failed": "Update action failed",
        "running": "Update currently running",
    }.get(source, source)
    brew_rows = "".join(f"<tr><td>{idx}</td><td>{html.escape(item)}</td></tr>" for idx, item in enumerate(brew_items, 1)) or '<tr><td colspan="2">No Homebrew package names available.</td></tr>'
    body = f'''
<section class="grid">
  <div class="card"><span>Displayed metric</span><strong>{html.escape(value)}</strong></div>
  <div class="card"><span>Selected source</span><strong>{html.escape(selected)}</strong></div>
  <div class="card"><span>Priority</span><strong>macOS → brew → Hermes</strong></div>
</section>
<section class="section"><h2>Current update precedence result</h2><p>{html.escape(detail)}</p></section>
<section class="section"><h2>Update source status</h2><table><tbody>
<tr><th>macOS</th><td>{html.escape(str(mac_value))} · count {html.escape(str(mac_count))}<br>{html.escape(mac_detail)}</td></tr>
<tr><th>Homebrew</th><td>count {html.escape(str(brew_count))}<br>{html.escape(brew_detail)}</td></tr>
<tr><th>Hermes Agent</th><td>{html.escape('Update available' if hermes_available else 'No update selected')}<br>{html.escape(hermes_detail)}</td></tr>
</tbody></table></section>
<section class="section"><h2>Homebrew outdated packages</h2><table><thead><tr><th>#</th><th>Package</th></tr></thead><tbody>{brew_rows}</tbody></table></section>'''
    return metric_detail_shell("Updates", "Metric detail", body)


def render_hermes_backups_detail() -> bytes:
    rows, meta = backup_inventory()
    row_html = "".join(
        f"<tr><td>{html.escape(format_iso_timestamp(row['created'].astimezone()))}</td>"
        f"<td><span class='badge{' warn' if not row['ok'] else ''}'>{html.escape(row['rating'])}</span></td>"
        f"<td>{html.escape(human_size(row['size']))}</td>"
        f"<td><code>{html.escape(str(row['archive']))}</code></td>"
        f"<td><code>{html.escape(str(row['checksum']))}</code><br><code>{html.escape(str(row['restore']))}</code></td>"
        f"<td>{html.escape(', '.join(row['missing']) if row['missing'] else 'Complete set + success log entry')}</td></tr>"
        for row in rows
    ) or '<tr><td colspan="6">No Hermes backup artifacts found.</td></tr>'
    latest = rows[0] if rows else None
    latest_label = relative_time_label(latest['created'].timestamp()) if latest else 'None'
    body = f'''
<section class="grid">
  <div class="card"><span>Latest backup</span><strong>{html.escape(latest_label)}</strong></div>
  <div class="card"><span>Successful backups</span><strong>{meta['successful']}/{meta['total']}</strong></div>
  <div class="card"><span>Success rating</span><strong>{meta['rating_percent']}%</strong></div>
</section>
<section class="section"><h2>Backup locations</h2><table><tbody>
<tr><th>Backup directory</th><td><code>{html.escape(str(meta['directory']))}</code></td></tr>
<tr><th>Mac mini backup directory</th><td><code>{html.escape(str(meta['remote_location']))}</code></td></tr>
<tr><th>Backup log</th><td><code>{html.escape(str(meta['log_file']))}</code></td></tr>
<tr><th>Expected backup set</th><td>Unencrypted archive <code>.tar.zst</code> (legacy encrypted <code>.tar.zst.enc</code> sets still listed), checksum <code>.sha256</code>, restore notes <code>.RESTORE.txt</code>, and success log entry.</td></tr>
</tbody></table></section>
<section class="section"><h2>Hermes backup inventory</h2><table><thead><tr><th>Created</th><th>Rating</th><th>Size</th><th>Archive</th><th>Companion files</th><th>Validation detail</th></tr></thead><tbody>{row_html}</tbody></table></section>
<section class="section"><h2>Recent backup log tail</h2><pre>{html.escape(str(meta['log_tail'] or 'No log content available.'))}</pre></section>'''
    return metric_detail_shell("Last Hermes Backup", "Metric detail", body)


def render_system_uptime_detail() -> bytes:
    value, detail, warning = system_uptime_metric()
    fan_running, fan_detail = macs_fan_control_status()
    fan_status = "Running" if fan_running else "Not running"
    body = f'''<section class="grid"><div class="card"><span>Displayed metric</span><strong>{html.escape(value)}</strong></div><div class="card"><span>Macs Fan Control</span><strong>{html.escape(fan_status)}</strong></div><div class="card"><span>Host</span><strong>{html.escape(socket.gethostname())}</strong></div></section><section class="section"><h2>Detail</h2><p>{html.escape(detail)}</p><p>{html.escape(fan_detail)}</p><p>Uptime is collected from <code>/usr/sbin/sysctl -n kern.boottime</code>. If Macs Fan Control is not running, this metric intentionally shows a warning instead of uptime.</p></section>'''
    return metric_detail_shell("System Uptime", "Metric detail", body)


def render_local_disk_detail() -> bytes:
    free, total, pct = local_disk_usage_metric()
    used = max(0, total - free)
    top_dirs, top_files, warnings, inventory_generated = local_disk_inventory()
    warning_html = ""
    if warnings:
        warning_html = '<section class="section"><span class="badge warn">Scan warning</span><p>' + html.escape(" · ".join(warnings)) + '</p></section>'
    body = f'''<section class="grid"><div class="card"><span>Free</span><strong>{human_size(free)}</strong></div><div class="card"><span>Total</span><strong>{human_size(total)}</strong></div><div class="card"><span>Percent free</span><strong>{pct:.1f}%</strong></div></section><section class="section"><h2>Volume detail</h2><table><tbody><tr><th>Measured path</th><td><code>{html.escape(str(HOME))}</code></td></tr><tr><th>Used</th><td>{human_size(used)}</td></tr><tr><th>Inventory generated</th><td>{html.escape(format_iso_timestamp(inventory_generated.astimezone()))}</td></tr><tr><th>Alert threshold</th><td>Amber/pink when free space is at or below 20%.</td></tr></tbody></table></section>{warning_html}<section class="section"><h2>Top 10 largest directories</h2><p>Recursive directory sizes under <code>{html.escape(str(HOME))}</code>, constrained to the same local filesystem.</p><table><thead><tr><th>#</th><th>Size</th><th>Directory</th></tr></thead><tbody>{disk_inventory_rows(top_dirs)}</tbody></table></section><section class="section"><h2>Top 10 largest files by disk used</h2><p>Allocated disk use under <code>{html.escape(str(HOME))}</code>, constrained to the same local filesystem. The logical-size column exposes sparse/virtual files such as Docker disk images that can advertise a much larger maximum capacity than they currently consume.</p><table><thead><tr><th>#</th><th>Disk used</th><th>Logical size</th><th>File</th></tr></thead><tbody>{disk_file_inventory_rows(top_files)}</tbody></table></section>'''
    return metric_detail_shell("Local Disk Free", "Metric detail", body)


def render_portal_update_detail(reports: list[Report]) -> bytes:
    ts = portal_last_updated(reports)
    if ts:
        update_dt = dt.datetime.fromtimestamp(ts).astimezone()
        age_seconds = max(0.0, (dt.datetime.now().astimezone() - update_dt).total_seconds())
        value = update_time_label(ts)
        detail = f"{int(age_seconds // 60)} minutes ago"
    else:
        update_dt = None
        age_seconds = 0
        value = "None"
        detail = "No update marker found"
    body = f'''<section class="grid"><div class="card"><span>Latest update</span><strong>{html.escape(value)}</strong></div><div class="card"><span>Age</span><strong>{html.escape(detail)}</strong></div><div class="card"><span>Reports indexed</span><strong>{len(reports)}</strong></div></section><section class="section"><h2>Portal update detail</h2><table><tbody><tr><th>Marker file</th><td><code>{html.escape(str(LAST_UPDATED_FILE))}</code></td></tr><tr><th>Exact timestamp</th><td>{html.escape(format_iso_timestamp(update_dt) if update_dt else 'None')}</td></tr><tr><th>Alert threshold</th><td>Amber/pink when older than 1 hour.</td></tr></tbody></table></section>'''
    return metric_detail_shell("Latest Portal Update", "Metric detail", body)


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
    if not isinstance(value, dict):
        return None
    raw_status = str(value.get("status") or "open").strip().lower()
    if raw_status not in {"open", "acknowledged", "suppressed"}:
        return None
    try:
        repeat_count = max(0, int(value.get("repeat_count") or value.get("acknowledged_count") or 0))
    except (TypeError, ValueError):
        repeat_count = 0
    reason = str(value.get("reason") or "").strip()[:140]
    return {
        "status": raw_status,
        "repeat_count": repeat_count,
        "reason": reason,
        "updated_at": str(value.get("updated_at") or now or now_iso_utc()),
    }


def ensure_soc_alert_status_table(conn: sqlite3.Connection) -> None:
    """Create analyst state tables inside the alert store database.

    `analyst_alert_status` is the original per-rendered-row table. It is kept
    for backward compatibility. `analyst_alert_group_state` is the durable
    group-level state table used by the API and multi-analyst UI path.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analyst_alert_status (
          alert_id TEXT PRIMARY KEY,
          status TEXT NOT NULL CHECK(status IN ('acknowledged', 'suppressed')),
          repeat_count INTEGER NOT NULL DEFAULT 0,
          reason TEXT,
          updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_analyst_alert_status_status ON analyst_alert_status(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_analyst_alert_status_updated_at ON analyst_alert_status(updated_at)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analyst_alert_group_state (
          group_id TEXT PRIMARY KEY,
          group_key TEXT,
          status TEXT NOT NULL CHECK(status IN ('acknowledged', 'suppressed')),
          repeat_count INTEGER NOT NULL DEFAULT 0,
          reason TEXT,
          updated_at TEXT NOT NULL,
          updated_by TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_group_state_status ON analyst_alert_group_state(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_group_state_updated_at ON analyst_alert_group_state(updated_at)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analyst_adjudications (
          adjudication_id TEXT PRIMARY KEY,
          dashboard_group_id TEXT NOT NULL,
          stable_group_id TEXT NOT NULL,
          case_id TEXT,
          analysis_id TEXT NOT NULL,
          outcome_override TEXT NOT NULL,
          confidence TEXT NOT NULL,
          rationale TEXT NOT NULL,
          evidence_gap TEXT,
          next_action TEXT,
          reviewer TEXT NOT NULL,
          event_status TEXT,
          detection_validity TEXT,
          activity_disposition TEXT,
          handling TEXT,
          duplicate_of TEXT,
          case_resolution_reason TEXT,
          created_at TEXT NOT NULL
        )
        """
    )
    adjudication_columns = {
        str(row[1]) for row in conn.execute(
            "PRAGMA table_info(analyst_adjudications)"
        ).fetchall()
    }
    for column in (
        "event_status",
        "detection_validity",
        "activity_disposition",
        "handling",
        "duplicate_of",
    ):
        if column not in adjudication_columns:
            conn.execute(
                f"ALTER TABLE analyst_adjudications ADD COLUMN {column} TEXT"
            )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_analyst_adjudications_group_created "
        "ON analyst_adjudications(dashboard_group_id, created_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_analyst_adjudications_analysis_created "
        "ON analyst_adjudications(analysis_id, created_at DESC)"
    )


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
    if not group_key:
        return ""
    group_expr = soc_alert_group_key_sql()
    try:
        row = conn.execute(
            f"""
            SELECT enrichment_json
            FROM alerts
            WHERE {group_expr} = ?
              AND enrichment_json IS NOT NULL
              AND TRIM(enrichment_json) != ''
            ORDER BY
              CASE
                WHEN COALESCE(json_array_length(json_extract(enrichment_json, '$.external_intel.records')), 0) > 0 THEN 0
                WHEN COALESCE(json_array_length(json_extract(enrichment_json, '$.external_intel.errors')), 0) > 0 THEN 1
                WHEN COALESCE(json_array_length(json_extract(enrichment_json, '$.external_intel.skipped')), 0) > 0 THEN 2
                ELSE 3
              END,
              replace(replace(COALESCE(last_seen, timestamp, first_seen), 'T', ' '), 'Z', '') DESC,
              alert_id DESC
            LIMIT 1
            """,
            (group_key,),
        ).fetchone()
    except sqlite3.Error:
        return ""
    return str(row["enrichment_json"] or "") if row else ""


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
    keys = list(dict.fromkeys(str(value or "").strip() for value in group_keys if str(value or "").strip()))
    if not keys:
        return {}

    group_expr = soc_alert_group_key_sql()
    placeholders = ",".join("?" for _ in keys)
    try:
        rows = conn.execute(
            f"""
            WITH ranked_enrichment AS (
              SELECT
                {group_expr} AS resolved_group_key,
                enrichment_json,
                ROW_NUMBER() OVER (
                  PARTITION BY {group_expr}
                  ORDER BY
                    CASE
                      WHEN COALESCE(json_array_length(json_extract(enrichment_json, '$.external_intel.records')), 0) > 0 THEN 0
                      WHEN COALESCE(json_array_length(json_extract(enrichment_json, '$.external_intel.errors')), 0) > 0 THEN 1
                      WHEN COALESCE(json_array_length(json_extract(enrichment_json, '$.external_intel.skipped')), 0) > 0 THEN 2
                      ELSE 3
                    END,
                    replace(replace(COALESCE(last_seen, timestamp, first_seen), 'T', ' '), 'Z', '') DESC,
                    alert_id DESC
                ) AS enrichment_rank
              FROM alerts
              WHERE {group_expr} IN ({placeholders})
                AND enrichment_json IS NOT NULL
                AND TRIM(enrichment_json) != ''
            )
            SELECT resolved_group_key, enrichment_json
            FROM ranked_enrichment
            WHERE enrichment_rank = 1
            """,
            keys,
        ).fetchall()
    except sqlite3.Error:
        return {}
    return {
        str(row["resolved_group_key"]): str(row["enrichment_json"] or "")
        for row in rows
        if row["resolved_group_key"]
    }


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
    try:
        number = int(round(float(value)))
    except (TypeError, ValueError):
        number = default
    return max(low, min(high, number))


def pcap_request_id(seed: dict) -> str:
    raw = json.dumps(seed, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def normalize_pcap_timestamp(value: object) -> str:
    if not value:
        return ""
    try:
        return format_iso_timestamp(parse_iso_timestamp(value), utc_z=True)
    except Exception:
        return ""


def pcap_capture_file_from_json(*values: object) -> str | None:
    for value in values:
        if not value:
            continue
        try:
            parsed = json.loads(str(value))
        except (TypeError, ValueError):
            continue
        if not isinstance(parsed, dict):
            continue
        for path in (
            ("suricata", "capture_file"),
            ("capture_file",),
        ):
            current = parsed
            for key in path:
                current = current.get(key) if isinstance(current, dict) else None
            if current:
                return str(current)[:512]
    return None


def pcap_request_candidate_from_group(conn: sqlite3.Connection, group_id: str) -> dict:
    if not sqlite_table_exists(conn, "alert_group_summary"):
        return {}
    columns = sqlite_table_columns(conn, "alert_group_summary")
    network_protocol_sql = "network_protocol" if "network_protocol" in columns else "NULL AS network_protocol"
    row = conn.execute(
        f"""
        SELECT group_id, group_key, representative_alert_id, first_seen, last_seen,
               timestamp, source_ip, source_port, destination_ip, destination_port,
               {network_protocol_sql}, transport_protocol
        FROM alert_group_summary
        WHERE group_id = ?
        """,
        (group_id,),
    ).fetchone()
    if not row:
        return {}
    candidate = {
        "alert_id": row["representative_alert_id"],
        "group_id": row["group_id"],
        "group_key": row["group_key"],
        "first_seen": row["first_seen"] or row["timestamp"],
        "last_seen": row["last_seen"] or row["timestamp"],
        "source_ip": row["source_ip"],
        "source_port": row["source_port"],
        "destination_ip": row["destination_ip"],
        "destination_port": row["destination_port"],
        "network_protocol": row["network_protocol"],
        "transport_protocol": row["transport_protocol"],
        "community_id": None,
    }
    if sqlite_table_exists(conn, "alerts") and row["representative_alert_id"]:
        alert_columns = sqlite_table_columns(conn, "alerts")
        select_parts = [
            "alert_id",
            "first_seen" if "first_seen" in alert_columns else "NULL AS first_seen",
            "last_seen" if "last_seen" in alert_columns else "NULL AS last_seen",
            "timestamp" if "timestamp" in alert_columns else "NULL AS timestamp",
            "source_ip" if "source_ip" in alert_columns else "NULL AS source_ip",
            "source_port" if "source_port" in alert_columns else "NULL AS source_port",
            "destination_ip" if "destination_ip" in alert_columns else "NULL AS destination_ip",
            "destination_port" if "destination_port" in alert_columns else "NULL AS destination_port",
            "network_protocol" if "network_protocol" in alert_columns else "NULL AS network_protocol",
            "transport_protocol" if "transport_protocol" in alert_columns else "NULL AS transport_protocol",
            "alert_json" if "alert_json" in alert_columns else "NULL AS alert_json",
            "raw_event_json" if "raw_event_json" in alert_columns else "NULL AS raw_event_json",
        ]
        alert_row = conn.execute(
            f"SELECT {', '.join(select_parts)} FROM alerts WHERE alert_id = ?",
            (row["representative_alert_id"],),
        ).fetchone()
        if alert_row:
            candidate.update({
                "alert_id": alert_row["alert_id"] or candidate["alert_id"],
                "first_seen": alert_row["first_seen"] or alert_row["timestamp"] or candidate["first_seen"],
                "last_seen": alert_row["last_seen"] or alert_row["timestamp"] or candidate["last_seen"],
                "source_ip": alert_row["source_ip"] or candidate["source_ip"],
                "source_port": alert_row["source_port"] if alert_row["source_port"] is not None else candidate["source_port"],
                "destination_ip": alert_row["destination_ip"] or candidate["destination_ip"],
                "destination_port": alert_row["destination_port"] if alert_row["destination_port"] is not None else candidate["destination_port"],
                "network_protocol": alert_row["network_protocol"] or candidate["network_protocol"],
                "transport_protocol": alert_row["transport_protocol"] or candidate["transport_protocol"],
                "capture_file": pcap_capture_file_from_json(alert_row["raw_event_json"], alert_row["alert_json"]),
            })
    return candidate


def normalize_pcap_request(payload: dict, candidate: dict) -> tuple[dict | None, str]:
    merged = {**candidate, **(payload or {})}
    reason = str(merged.get("reason") or "SOC analyst requested PCAP evidence").strip()[:240]
    source_ip = str(merged.get("source_ip") or "").strip()[:64]
    destination_ip = str(merged.get("destination_ip") or "").strip()[:64]
    first_seen = normalize_pcap_timestamp(merged.get("first_seen") or merged.get("timestamp") or merged.get("last_seen"))
    last_seen = normalize_pcap_timestamp(merged.get("last_seen") or merged.get("timestamp") or merged.get("first_seen"))
    if not source_ip or not destination_ip:
        return None, "PCAP request requires source and destination IPs"
    if not first_seen or not last_seen:
        return None, "PCAP request requires first_seen and last_seen timestamps"

    request = {
        "alert_id": str(merged.get("alert_id") or "").strip()[:512] or None,
        "group_id": str(merged.get("group_id") or "").strip()[:64] or None,
        "group_key": str(merged.get("group_key") or "").strip()[:512] or None,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "source_ip": source_ip,
        "source_port": bounded_int(merged.get("source_port"), 0, 0, 65535) or None,
        "destination_ip": destination_ip,
        "destination_port": bounded_int(merged.get("destination_port"), 0, 0, 65535) or None,
        "network_protocol": str(merged.get("network_protocol") or "").strip()[:32] or None,
        "transport_protocol": str(merged.get("transport_protocol") or "").strip().lower()[:32] or None,
        "community_id": str(merged.get("community_id") or "").strip()[:128] or None,
        "capture_file": str(merged.get("capture_file") or "").strip()[:512] or None,
        "requested_by": str(merged.get("requested_by") or "dashboard").strip()[:80] or "dashboard",
        "reason": reason,
        "max_window_seconds": bounded_int(merged.get("max_window_seconds"), 120, 30, 300),
        "require_source_port": bool(merged.get("require_source_port")),
    }
    request["request_id"] = pcap_request_id({
        "alert_id": request["alert_id"],
        "group_id": request["group_id"],
        "first_seen": request["first_seen"],
        "last_seen": request["last_seen"],
        "source_ip": request["source_ip"],
        "source_port": request["source_port"],
        "destination_ip": request["destination_ip"],
        "destination_port": request["destination_port"],
        "community_id": request["community_id"],
        "capture_file": request["capture_file"],
        "reason": request["reason"],
    })
    return request, ""


def insert_pcap_request(conn: sqlite3.Connection, request: dict) -> sqlite3.Row:
    columns = sqlite_table_columns(conn, "pcap_requests")
    if not columns:
        raise sqlite3.Error("pcap_requests table is unavailable")
    now = now_iso_utc()
    values = {
        "request_id": request["request_id"],
        "status": "pending",
        "alert_id": request["alert_id"],
        "group_id": request["group_id"],
        "group_key": request["group_key"],
        "first_seen": request["first_seen"],
        "last_seen": request["last_seen"],
        "source_ip": request["source_ip"],
        "source_port": request["source_port"],
        "destination_ip": request["destination_ip"],
        "destination_port": request["destination_port"],
        "network_protocol": request["network_protocol"],
        "transport_protocol": request["transport_protocol"],
        "community_id": request["community_id"],
        "requested_by": request["requested_by"],
        "reason": request["reason"],
        "max_window_seconds": request["max_window_seconds"],
        "request_json": json.dumps(request, separators=(",", ":"), sort_keys=True),
        "created_at": now,
        "updated_at": now,
        "claimed_at": None,
        "completed_at": None,
        "error": None,
        "artifact_path": None,
        "artifact_sha256": None,
        "artifact_size_bytes": None,
    }
    insert_columns = [column for column in values if column in columns]
    placeholders = ", ".join("?" for _ in insert_columns)
    update_columns = [
        column for column in (
            "status", "reason", "requested_by", "max_window_seconds", "request_json",
            "updated_at", "claimed_at", "completed_at", "error", "artifact_path",
            "artifact_sha256", "artifact_size_bytes",
        )
        if column in columns
    ]
    updates = ", ".join(f"{column} = excluded.{column}" for column in update_columns)
    conn.execute(
        f"""
        INSERT INTO pcap_requests ({", ".join(insert_columns)})
        VALUES ({placeholders})
        ON CONFLICT(request_id) DO UPDATE SET {updates}
        """,
        [values[column] for column in insert_columns],
    )
    return conn.execute("SELECT * FROM pcap_requests WHERE request_id = ?", (request["request_id"],)).fetchone()


class AlertStoreRequestError(RuntimeError):
    """Preserve an alert-store HTTP status without exposing response bodies."""

    def __init__(self, detail: str, status_code: int = 503):
        super().__init__(detail)
        self.status_code = int(status_code)


def asset_store_write_token() -> str:
    """Read the owner-controlled local asset-write credential without exporting it."""
    configured = str(os.environ.get("ASSET_STORE_WRITE_TOKEN") or "").strip()
    if configured:
        if len(configured) < 32:
            raise RuntimeError("asset-store write credential is invalid")
        return configured
    path = Path(ASSET_STORE_ENV_FILE)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RuntimeError("asset-store write credential is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > 1024 * 1024
    ):
        raise RuntimeError("asset-store environment file is not owner-controlled")
    values: dict[str, str] = {}
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            cleaned = value.strip()
            if (
                len(cleaned) >= 2
                and cleaned[0] == cleaned[-1]
                and cleaned[0] in {"'", '"'}
            ):
                cleaned = cleaned[1:-1]
            values[key.strip()] = cleaned
    except OSError as exc:
        raise RuntimeError("asset-store write credential is unavailable") from exc
    token = values.get("ASSET_STORE_WRITE_TOKEN") or values.get(
        "N8N_POST_COMMIT_TOKEN",
        "",
    )
    if len(token) < 32:
        raise RuntimeError("asset-store write credential is invalid")
    return token


def asset_store_post_json(path: str, payload: dict, timeout: float = 10.0) -> dict:
    """Send one authenticated asset mutation to the loopback alert-store."""
    if path not in {
        "/assets/promote-dhcp",
        "/assets/approve-dhcp-ip-change",
        "/assets/update",
        "/assets/demote",
    }:
        raise ValueError("asset-store mutation path is not allowlisted")
    encoded = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(encoded)),
        "X-Onion-Sentinel-Asset-Token": asset_store_write_token(),
    }
    req = urllib_request.Request(
        f"{SOC_ALERT_STORE_API_URL}{path}",
        data=encoded,
        method="POST",
        headers=headers,
    )
    try:
        with urllib_request.urlopen(req, timeout=timeout) as response:
            result = read_bounded_json(
                response,
                max_bytes=SOC_ALERT_STORE_RESPONSE_MAX_BYTES,
            )
    except urllib_error.HTTPError as exc:
        try:
            error_payload = read_bounded_json(
                exc,
                max_bytes=SOC_ALERT_STORE_RESPONSE_MAX_BYTES,
            )
            detail = str(
                error_payload.get("reason")
                or error_payload.get("error")
                or exc.reason
            )
        except (OSError, BoundedResponseError, json.JSONDecodeError):
            detail = str(exc.reason)
        raise AlertStoreRequestError(
            detail[:500],
            int(exc.code or 503),
        ) from exc
    except (OSError, urllib_error.URLError, json.JSONDecodeError) as exc:
        raise AlertStoreRequestError(str(exc)[:500], 503) from exc
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise AlertStoreRequestError("asset-store rejected request", 400)
    return result


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
    """Bound the operator review payload before it reaches the asset store."""
    if not isinstance(payload, dict):
        raise ValueError("Request body must be a JSON object.")
    allowed = {
        "discovery_id",
        "expected_ip",
        "expected_mac",
        "expected_hostname",
        "asset_id",
        "operator_ref",
        "reason",
        "confirm",
    }
    if action == "promote":
        allowed |= {
            "hostname",
            "role",
            "platform",
            "criticality",
            "owner_ref",
            "accept_locally_administered_mac",
        }
    unknown = set(payload) - allowed
    if unknown:
        raise ValueError("Request contains unsupported asset review fields.")

    limits = {
        "discovery_id": 20,
        "expected_ip": 64,
        "expected_mac": 17,
        "expected_hostname": 253,
        "asset_id": 160,
        "operator_ref": 160,
        "reason": 1000,
        "confirm": 256,
        "hostname": 253,
        "role": 160,
        "platform": 160,
        "criticality": 16,
        "owner_ref": 300,
    }
    result = {
        key: str(payload.get(key) or "").strip()[: maximum + 1]
        for key, maximum in limits.items()
        if key in allowed
    }
    for key, maximum in limits.items():
        if key in result and len(result[key]) > maximum:
            raise ValueError(f"{key} exceeds its maximum length.")
    required = {
        "discovery_id",
        "expected_ip",
        "asset_id",
        "operator_ref",
        "reason",
        "confirm",
    }
    if action == "promote":
        required |= {"expected_mac", "role"}
    missing = sorted(key for key in required if not result.get(key))
    if missing:
        raise ValueError(
            f"Required asset review field is missing: {missing[0]}."
        )
    if not re.fullmatch(r"[0-9a-f]{20}", result["discovery_id"]):
        raise ValueError("discovery_id is invalid.")
    try:
        result["expected_ip"] = str(
            ipaddress.ip_address(result["expected_ip"])
        )
    except ValueError as exc:
        raise ValueError("expected_ip is invalid.") from exc
    mac = result.get("expected_mac", "").lower().replace("-", ":")
    if mac and not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        raise ValueError("expected_mac is invalid.")
    result["expected_mac"] = mac
    result["expected_hostname"] = (
        result.get("expected_hostname", "").rstrip(".").lower()
    )
    if action == "promote":
        criticality = result.get("criticality") or "unknown"
        if criticality not in {
            "low",
            "medium",
            "high",
            "critical",
            "unknown",
        }:
            raise ValueError("criticality is invalid.")
        result["criticality"] = criticality
        result["accept_locally_administered_mac"] = (
            payload.get("accept_locally_administered_mac") is True
        )
    return result


def asset_dhcp_promotion_response(payload: object) -> tuple[int, dict]:
    try:
        normalized = _normalized_asset_review_payload(
            payload,
            action="promote",
        )
        result = asset_store_post_json("/assets/promote-dhcp", normalized)
    except ValueError as exc:
        return HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)}
    except (RuntimeError, AlertStoreRequestError) as exc:
        return int(getattr(exc, "status_code", 503)), {
            "ok": False,
            "error": str(exc),
        }
    with ASSET_INVENTORY_CACHE_LOCK:
        ASSET_INVENTORY_CACHE.clear()
        ASSET_INVENTORY_CACHE.update(
            {"signature": None, "inventory": None, "expires_at": 0.0}
        )
    return HTTPStatus.CREATED, result


def asset_dhcp_ip_change_response(payload: object) -> tuple[int, dict]:
    try:
        normalized = _normalized_asset_review_payload(
            payload,
            action="ip_change",
        )
        result = asset_store_post_json(
            "/assets/approve-dhcp-ip-change",
            normalized,
        )
    except ValueError as exc:
        return HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)}
    except (RuntimeError, AlertStoreRequestError) as exc:
        return int(getattr(exc, "status_code", 503)), {
            "ok": False,
            "error": str(exc),
        }
    with ASSET_INVENTORY_CACHE_LOCK:
        ASSET_INVENTORY_CACHE.clear()
        ASSET_INVENTORY_CACHE.update(
            {"signature": None, "inventory": None, "expires_at": 0.0}
        )
    return HTTPStatus.CREATED, result


def _normalized_asset_mutation_payload(
    payload: object,
    *,
    action: str,
) -> dict:
    """Bound an operator edit or demotion before the database transaction."""
    if not isinstance(payload, dict):
        raise ValueError("Request body must be a JSON object.")
    common = {
        "asset_id",
        "expected_valid_from",
        "operator_ref",
        "reason",
        "confirm",
    }
    allowed = set(common)
    if action == "edit":
        allowed |= {
            "ip_addresses",
            "mac_addresses",
            "hostnames",
            "role",
            "platform",
            "criticality",
            "confidence",
        }
    if set(payload) - allowed:
        raise ValueError("Request contains unsupported asset mutation fields.")
    limits = {
        "asset_id": 160,
        "expected_valid_from": 64,
        "operator_ref": 160,
        "reason": 1000,
        "confirm": 256,
        "role": 160,
        "platform": 160,
        "criticality": 16,
        "confidence": 16,
    }
    result = {
        key: str(payload.get(key) or "").strip()[: maximum + 1]
        for key, maximum in limits.items()
        if key in allowed
    }
    for key, maximum in limits.items():
        if key in result and len(result[key]) > maximum:
            raise ValueError(f"{key} exceeds its maximum length.")
    missing = sorted(key for key in common if not result.get(key))
    if missing:
        raise ValueError(
            f"Required asset mutation field is missing: {missing[0]}."
        )
    try:
        parsed = parse_iso_timestamp(result["expected_valid_from"])
    except (TypeError, ValueError) as exc:
        raise ValueError("expected_valid_from is invalid.") from exc
    if parsed.tzinfo is None:
        raise ValueError("expected_valid_from is invalid.")
    result["expected_valid_from"] = parsed.astimezone(
        dt.timezone.utc
    ).isoformat().replace("+00:00", "Z")
    expected_confirmation = (
        f"EDIT:{result['asset_id']}"
        if action == "edit"
        else f"DEMOTE:{result['asset_id']}"
    )
    if result["confirm"] != expected_confirmation:
        raise ValueError(
            f"Confirmation must exactly match {expected_confirmation}."
        )
    if action != "edit":
        return result

    def bounded_list(
        key: str,
        maximum: int,
        *,
        normalizer=None,
    ) -> list[str]:
        raw = payload.get(key)
        if not isinstance(raw, list) or len(raw) > 64:
            raise ValueError(f"{key} must be a bounded list.")
        values = []
        for item in raw:
            value = str(item or "").strip()
            if not value or len(value) > maximum:
                raise ValueError(f"{key} contains an invalid value.")
            if normalizer is not None:
                value = normalizer(value)
            if value not in values:
                values.append(value)
        return values

    def normalize_ip(value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("ip_addresses contains an invalid address.") from exc

    def normalize_mac(value: str) -> str:
        normalized = value.lower().replace("-", ":")
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", normalized):
            raise ValueError("mac_addresses contains an invalid address.")
        if int(normalized.split(":", 1)[0], 16) & 1:
            raise ValueError("multicast MAC addresses cannot identify assets.")
        return normalized

    def normalize_hostname(value: str) -> str:
        normalized = value.rstrip(".").lower()
        if not normalized:
            raise ValueError("hostnames contains an invalid value.")
        return normalized

    result["ip_addresses"] = bounded_list(
        "ip_addresses",
        64,
        normalizer=normalize_ip,
    )
    result["mac_addresses"] = bounded_list(
        "mac_addresses",
        17,
        normalizer=normalize_mac,
    )
    result["hostnames"] = bounded_list(
        "hostnames",
        253,
        normalizer=normalize_hostname,
    )
    if not (
        result["ip_addresses"]
        or result["mac_addresses"]
        or result["hostnames"]
    ):
        raise ValueError("An asset must retain at least one identifier.")
    if not result.get("role"):
        raise ValueError("role is required.")
    if result.get("criticality") not in {
        "low", "medium", "high", "critical", "unknown"
    }:
        raise ValueError("criticality is invalid.")
    if result.get("confidence") not in {
        "low", "medium", "high", "unknown"
    }:
        raise ValueError("confidence is invalid.")
    return result


def asset_update_response(payload: object) -> tuple[int, dict]:
    try:
        normalized = _normalized_asset_mutation_payload(
            payload,
            action="edit",
        )
        result = asset_store_post_json("/assets/update", normalized)
    except ValueError as exc:
        return HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)}
    except (RuntimeError, AlertStoreRequestError) as exc:
        return int(getattr(exc, "status_code", 503)), {
            "ok": False,
            "error": str(exc),
        }
    with ASSET_INVENTORY_CACHE_LOCK:
        ASSET_INVENTORY_CACHE.clear()
        ASSET_INVENTORY_CACHE.update(
            {"signature": None, "inventory": None, "expires_at": 0.0}
        )
    return HTTPStatus.OK, result


def asset_demote_response(payload: object) -> tuple[int, dict]:
    try:
        normalized = _normalized_asset_mutation_payload(
            payload,
            action="demote",
        )
        result = asset_store_post_json("/assets/demote", normalized)
    except ValueError as exc:
        return HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)}
    except (RuntimeError, AlertStoreRequestError) as exc:
        return int(getattr(exc, "status_code", 503)), {
            "ok": False,
            "error": str(exc),
        }
    with ASSET_INVENTORY_CACHE_LOCK:
        ASSET_INVENTORY_CACHE.clear()
        ASSET_INVENTORY_CACHE.update(
            {"signature": None, "inventory": None, "expires_at": 0.0}
        )
    return HTTPStatus.OK, result


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


def soc_alert_pcap_request_response(group_id: str, payload: dict) -> tuple[int, dict]:
    group_id = str(group_id or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{12}", group_id):
        return soc_alert_api_error("Invalid SOC alert group id")
    if SOC_ALERT_STORE_API_URL:
        try:
            data = alert_store_post_json("/pcap/request", {**payload, "group_id": group_id})
        except RuntimeError as exc:
            return soc_alert_api_error(f"Alert-store PCAP request failed: {exc}", 503)
        data.update({"pcap_status_key": "queued", "pcap_status_label": "Queued"})
        return 202, data
    try:
        with soc_alert_db_write_connect() as conn:
            if not sqlite_table_exists(conn, "pcap_requests"):
                return soc_alert_api_error("PCAP broker queue is unavailable", 503)
            candidate = pcap_request_candidate_from_group(conn, group_id)
            if not candidate:
                return soc_alert_api_error("SOC alert group not found", 404)
            request, error = normalize_pcap_request(payload, {**candidate, "group_id": group_id})
            if not request:
                return soc_alert_api_error(error)
            row = insert_pcap_request(conn, request)
    except Exception as exc:
        return soc_alert_api_error(str(exc), 503)
    return 202, {
        "ok": True,
        "status": row["status"] if row else "pending",
        "pcap_status_key": "queued",
        "pcap_status_label": "Queued",
        "request": {key: row[key] for key in row.keys()} if row else request,
    }


def soc_alert_group_summary_available(conn: sqlite3.Connection) -> bool:
    """Return true when alert-store has populated the fast grouped summary."""
    if not sqlite_table_exists(conn, "alert_group_summary"):
        return False
    try:
        row = conn.execute("SELECT COUNT(*) FROM alert_group_summary").fetchone()
    except sqlite3.Error:
        return False
    return bool(row and int(row[0] or 0) > 0)


def soc_alert_group_counts(conn: sqlite3.Connection) -> dict[str, int]:
    """Return current grouped repeat counts, keyed by group_id."""
    if soc_alert_group_summary_available(conn):
        try:
            rows = conn.execute(
                """
                SELECT group_id,
                       MAX(raw_alert_count, COALESCE(total_seen_count, 0)) AS repeat_count
                FROM alert_group_summary
                """
            ).fetchall()
            return {row["group_id"]: int(row["repeat_count"] or 0) for row in rows}
        except sqlite3.Error:
            pass
    group_expr = soc_alert_group_key_sql()
    try:
        rows = conn.execute(
            f"""
            SELECT {group_expr} AS group_key,
                   MAX(COUNT(*), COALESCE(SUM(MAX(1, COALESCE(seen_count, 1))), 0)) AS repeat_count
            FROM alerts
            GROUP BY group_key
            """
        ).fetchall()
    except sqlite3.Error:
        return {}
    return {soc_alert_group_id(row["group_key"]): int(row["repeat_count"] or 0) for row in rows}


def soc_alert_manually_escalated_group_ids(conn: sqlite3.Connection) -> set[str]:
    """Return every dashboard alias moved manually to Incident Responder."""
    if not (
        sqlite_table_exists(conn, "incident_response_cases")
        and sqlite_table_exists(conn, "incident_response_events")
    ):
        return set()
    try:
        rows = conn.execute(
            """
            SELECT c.dashboard_group_id, c.group_id AS stable_group_id, e.detail_json
            FROM incident_response_cases AS c
            JOIN incident_response_events AS e ON e.case_id = c.case_id
            WHERE e.event_type = 'escalated'
            """
        ).fetchall()
    except sqlite3.Error:
        return set()

    dashboard_group_ids: set[str] = set()
    stable_group_ids: set[str] = set()
    for row in rows:
        dashboard_group_id = str(row["dashboard_group_id"] or "").strip().lower()
        if re.fullmatch(r"[a-f0-9]{12}", dashboard_group_id):
            dashboard_group_ids.add(dashboard_group_id)
        stable_group_id = str(row["stable_group_id"] or "").strip()
        if stable_group_id:
            stable_group_ids.add(stable_group_id)
        try:
            detail = json.loads(row["detail_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            detail = {}
        event_group_id = str(detail.get("dashboard_group_id") or "").strip().lower() if isinstance(detail, dict) else ""
        if re.fullmatch(r"[a-f0-9]{12}", event_group_id):
            dashboard_group_ids.add(event_group_id)

    if stable_group_ids and sqlite_table_exists(conn, "alert_group_alias"):
        stable_ids = sorted(stable_group_ids)
        for start in range(0, len(stable_ids), 500):
            chunk = stable_ids[start:start + 500]
            placeholders = ",".join("?" for _ in chunk)
            try:
                alias_rows = conn.execute(
                    f"""
                    SELECT legacy_group_id
                    FROM alert_group_alias
                    WHERE stable_group_id IN ({placeholders})
                    """,
                    chunk,
                ).fetchall()
            except sqlite3.Error:
                continue
            dashboard_group_ids.update(
                str(row["legacy_group_id"]).strip().lower()
                for row in alias_rows
                if re.fullmatch(r"[a-f0-9]{12}", str(row["legacy_group_id"] or "").strip().lower())
            )
    return dashboard_group_ids


def soc_alert_active_group_ids(
    conn: sqlite3.Connection,
    statuses: dict,
    manually_escalated_group_ids: set[str] | None = None,
) -> set[str]:
    """Return grouped detections currently visible in the default active view."""
    hidden_group_ids = {
        group_id for group_id, meta in (statuses or {}).items()
        if isinstance(meta, dict) and meta.get("status") in {"acknowledged", "suppressed"}
    }
    hidden_group_ids.update(
        manually_escalated_group_ids
        if manually_escalated_group_ids is not None
        else soc_alert_manually_escalated_group_ids(conn)
    )
    if soc_alert_group_summary_available(conn):
        try:
            rows = conn.execute(
                """
                SELECT group_id
                FROM alert_group_summary
                WHERE lower(coalesce(filter_status, 'accepted')) != 'suppressed'
                """
            ).fetchall()
            return {row["group_id"] for row in rows if row["group_id"] not in hidden_group_ids}
        except sqlite3.Error:
            pass
    group_expr = soc_alert_group_key_sql()
    try:
        rows = conn.execute(
            f"""
            SELECT {group_expr} AS group_key,
                   lower(coalesce(filter_status, 'accepted')) AS filter_status
            FROM alerts
            GROUP BY group_key, filter_status
            HAVING filter_status != 'suppressed'
            """
        ).fetchall()
    except sqlite3.Error:
        return set()
    return {
        soc_alert_group_id(row["group_key"])
        for row in rows
        if soc_alert_group_id(row["group_key"]) not in hidden_group_ids
    }


def normalize_soc_group_statuses(conn: sqlite3.Connection) -> dict:
    """Load current group state and hide stale acknowledgements.

    Acknowledged detections should reappear when the matching grouped detection
    count increases. Suppressed detections remain hidden until explicitly
    exposed. Production deletion is owned by alert-store; portal reads must not
    become a second SQLite writer.
    """
    if not sqlite_table_exists(conn, "analyst_alert_group_state"):
        return {}
    counts = soc_alert_group_counts(conn)
    rows = conn.execute(
        """
        SELECT group_id, group_key, status, repeat_count, reason, updated_at, updated_by
        FROM analyst_alert_group_state
        WHERE status IN ('acknowledged', 'suppressed')
        """
    ).fetchall()
    statuses: dict[str, dict] = {}
    for row in rows:
        group_id = row["group_id"]
        status = row["status"]
        repeat_count = int(row["repeat_count"] or 0)
        current_count = counts.get(group_id, repeat_count)
        if status == "acknowledged" and current_count > repeat_count:
            continue
        statuses[group_id] = {
            "status": status,
            "repeat_count": repeat_count,
            "reason": row["reason"] or "",
            "updated_at": row["updated_at"],
            "updated_by": row["updated_by"] or "",
            "group_key": row["group_key"] or "",
        }
    return statuses


def load_soc_alert_statuses_from_db() -> dict:
    if not SOC_ALERT_STORE_DB.exists():
        return {}
    try:
        with soc_alert_db_connect() as conn:
            return normalize_soc_group_statuses(conn)
    except Exception:
        return {}


def write_soc_alert_status_json_snapshot(statuses: dict) -> None:
    SOC_ALERT_STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "ok": True,
        "updated_at": now_iso_utc(),
        "statuses": statuses,
    }
    tmp = SOC_ALERT_STATUS_FILE.with_suffix(SOC_ALERT_STATUS_FILE.suffix + f".{uuid.uuid4().hex}.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, SOC_ALERT_STATUS_FILE)
    try:
        SOC_ALERT_STATUS_FILE.chmod(0o600)
    except Exception:
        pass


def save_soc_alert_statuses_to_db(statuses: dict) -> None:
    """Persist offline DR-test state; production writes through alert-store."""
    if not SOC_ALERT_STORE_DB.parent.exists():
        return
    try:
        with soc_alert_db_write_connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            ensure_soc_alert_status_table(conn)
            for alert_id, raw_meta in statuses.items():
                meta = normalize_soc_alert_status_meta(raw_meta)
                group_id = str(alert_id)
                if not meta or meta["status"] == "open":
                    conn.execute("DELETE FROM analyst_alert_group_state WHERE group_id = ?", (group_id,))
                    continue
                group_key = str(raw_meta.get("group_key") or "") if isinstance(raw_meta, dict) else ""
                conn.execute(
                    """
                    INSERT INTO analyst_alert_group_state (
                      group_id, group_key, status, repeat_count, reason, updated_at, updated_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(group_id) DO UPDATE SET
                      group_key = excluded.group_key,
                      status = excluded.status,
                      repeat_count = excluded.repeat_count,
                      reason = excluded.reason,
                      updated_at = excluded.updated_at,
                      updated_by = excluded.updated_by
                    """,
                    (
                        group_id,
                        group_key,
                        meta["status"],
                        meta["repeat_count"],
                        meta["reason"],
                        meta["updated_at"],
                        str(raw_meta.get("updated_by") or "")[:80] if isinstance(raw_meta, dict) else "",
                    ),
                )
    except Exception:
        # Do not let a failed transaction be followed by a successful-looking
        # JSON mirror update.
        raise


def load_soc_alert_statuses() -> dict:
    """Load shared SOC alert status state, using JSON only if SQLite is absent."""
    if SOC_ALERT_STORE_DB.exists():
        return load_soc_alert_statuses_from_db()
    json_statuses: dict = {}
    try:
        data = json.loads(SOC_ALERT_STATUS_FILE.read_text(encoding="utf-8"))
        statuses = data.get("statuses", {}) if isinstance(data, dict) else {}
        json_statuses = statuses if isinstance(statuses, dict) else {}
    except Exception:
        json_statuses = {}
    return json_statuses


def save_soc_alert_statuses(statuses: dict) -> None:
    normalized_statuses: dict[str, dict] = {}
    for alert_id, raw_meta in statuses.items():
        meta = normalize_soc_alert_status_meta(raw_meta)
        if meta and meta["status"] != "open":
            normalized_statuses[str(alert_id)] = meta
    save_soc_alert_statuses_to_db(normalized_statuses)
    write_soc_alert_status_json_snapshot(normalized_statuses)


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
    if not SOC_ALERT_STORE_DB.parent.exists():
        return
    normalized = normalize_soc_alert_status_meta(meta)
    # Keep the post-commit read and atomic JSON mirror replacement in the same
    # in-process critical section as the SQLite transaction. Otherwise another
    # writer can begin journal/DDL setup while this request is opening its
    # read-only snapshot connection.
    with SOC_ALERT_DB_WRITE_LOCK:
        for attempt in range(1, SOC_ALERT_DB_WRITE_RETRY_ATTEMPTS + 1):
            try:
                with soc_alert_db_write_connect() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    ensure_soc_alert_status_table(conn)
                    if not normalized or normalized["status"] == "open":
                        conn.execute(
                            "DELETE FROM analyst_alert_group_state WHERE group_id = ?",
                            (alert_id,),
                        )
                    else:
                        group_key = (
                            str(meta.get("group_key") or "")
                            if isinstance(meta, dict)
                            else ""
                        )
                        updated_by = (
                            str(meta.get("updated_by") or "")[:80]
                            if isinstance(meta, dict)
                            else ""
                        )
                        conn.execute(
                            """
                            INSERT INTO analyst_alert_group_state (
                              group_id, group_key, status, repeat_count, reason, updated_at, updated_by
                            ) VALUES (?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(group_id) DO UPDATE SET
                              group_key = excluded.group_key,
                              status = excluded.status,
                              repeat_count = excluded.repeat_count,
                              reason = excluded.reason,
                              updated_at = excluded.updated_at,
                              updated_by = excluded.updated_by
                            """,
                            (
                                alert_id,
                                group_key,
                                normalized["status"],
                                normalized["repeat_count"],
                                normalized["reason"],
                                normalized["updated_at"],
                                updated_by,
                            ),
                        )
                break
            except sqlite3.OperationalError as exc:
                retryable = any(
                    marker in str(exc).lower()
                    for marker in (
                        "database is busy",
                        "database is locked",
                        "disk i/o error",
                    )
                )
                if (
                    not retryable
                    or attempt >= SOC_ALERT_DB_WRITE_RETRY_ATTEMPTS
                ):
                    raise
                time.sleep(
                    SOC_ALERT_DB_WRITE_RETRY_BASE_SECONDS * attempt
                )
        write_soc_alert_status_json_snapshot(load_soc_alert_statuses_from_db())


def soc_alert_status_response() -> dict:
    statuses = load_soc_alert_statuses()
    acknowledged_all = {
        alert_id for alert_id, meta in statuses.items()
        if isinstance(meta, dict) and meta.get("status") == "acknowledged"
    }
    suppressed_all = {
        alert_id for alert_id, meta in statuses.items()
        if isinstance(meta, dict) and meta.get("status") == "suppressed"
    }
    acknowledged = sorted(acknowledged_all)
    suppressed = sorted(suppressed_all)
    counts = {"open": 0, "acknowledged": len(acknowledged), "suppressed": len(suppressed)}
    try:
        with soc_alert_db_connect() as conn:
            group_counts = soc_alert_group_counts(conn)
            escalated_group_ids = soc_alert_manually_escalated_group_ids(conn)
            active_group_ids = soc_alert_active_group_ids(conn, statuses, escalated_group_ids)
        acknowledged = sorted(acknowledged_all.difference(escalated_group_ids))
        suppressed = sorted(suppressed_all.difference(escalated_group_ids))
        counts["open"] = len(active_group_ids)
        counts["acknowledged"] = len(acknowledged)
        counts["suppressed"] = len(suppressed)
        counts["escalated"] = len(set(group_counts).intersection(escalated_group_ids))
        counts["total"] = len(set(group_counts).difference(escalated_group_ids))
    except Exception:
        counts["total"] = len(statuses)
    return {
        "ok": True,
        "mode": "grouped",
        "statuses": statuses,
        "acknowledged": acknowledged,
        "suppressed": suppressed,
        "counts": counts,
    }


def llm_analysis_log_limit(raw: object) -> int:
    try:
        value = int(str(raw or 25))
    except ValueError:
        value = 25
    return max(1, min(50, value))


def llm_analysis_log_page(raw: object) -> int:
    try:
        value = int(str(raw or 1))
    except ValueError:
        value = 1
    return max(1, value)


def read_llm_analysis_logs(max_rows: int = 1000) -> list[dict]:
    """Read a bounded newest-first tail without retaining full history."""
    return SOC_ALERT_LLM_ANALYSIS_LOG_INDEX.tail(max_rows)


def current_llm_queue_size() -> int:
    static_status = read_soc_alert_json_file(SOC_ALERT_STATIC_STATUS_FILE)
    ai_counts = static_status.get("ai", {}).get("counts", {}) if isinstance(static_status, dict) else {}
    try:
        return max(0, int(ai_counts.get("queued") or 0))
    except (TypeError, ValueError):
        return 0


def read_bounded_llm_analysis_record(path: Path) -> dict:
    """Read one trusted local status record without accepting unbounded input."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(SOC_ALERT_LLM_ANALYSIS_RECORD_MAX_BYTES + 1)
        if len(raw) > SOC_ALERT_LLM_ANALYSIS_RECORD_MAX_BYTES:
            return {}
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def active_llm_analysis_record_paths() -> list[Path]:
    """Return a bounded newest-first set of regular per-run status files."""
    newest: list[tuple[int, str, Path]] = []
    try:
        with os.scandir(SOC_ALERT_LLM_ANALYSIS_ACTIVE_DIR) as entries:
            for entry in entries:
                if not entry.name.endswith(".json") or not entry.is_file(follow_symlinks=False):
                    continue
                try:
                    mtime_ns = entry.stat(follow_symlinks=False).st_mtime_ns
                except OSError:
                    continue
                item = (mtime_ns, entry.name, Path(entry.path))
                if len(newest) < SOC_ALERT_LLM_ANALYSIS_ACTIVE_LIMIT:
                    heapq.heappush(newest, item)
                elif item[:2] > newest[0][:2]:
                    heapq.heapreplace(newest, item)
    except OSError:
        return []
    return [item[2] for item in sorted(newest, reverse=True)]


def read_active_llm_analyses() -> list[dict]:
    """Read only live per-run records, using one bounded process snapshot."""
    records = [
        record
        for path in active_llm_analysis_record_paths()
        if (record := read_bounded_llm_analysis_record(path))
        and record.get("status") == "running"
    ]
    if not records:
        return []
    commands = llm_analysis_process_commands()
    active = [
        record
        for record in records
        if llm_analysis_process_active(
            str(record.get("prompt_package") or ""),
            commands,
            record.get("runner_pid"),
        )
    ]
    active.sort(key=lambda record: (
        str(record.get("started_at") or ""),
        str(record.get("log_id") or ""),
    ))
    return active


def llm_agent_execution_state(record: object) -> dict:
    """Describe the persisted agent/job owner for one observed execution."""
    current = record if isinstance(record, dict) else {}
    role = str(current.get("agent_role") or "").strip().lower().replace("_", "-")
    labels = {
        "soc-analyst": ("SOC Analyst", "ai_analysis", "SOC alert triage"),
        "incident-responder": (
            "Incident Responder",
            "incident_response_analysis",
            "Incident response investigation",
        ),
        "siem-engineer": (
            "SIEM Engineer",
            "siem_engineering",
            "Detection engineering analysis",
        ),
        "cyber-threat-intel": (
            "Cyber Threat Intel",
            "cyber_threat_intel",
            "Threat-intelligence analysis",
        ),
        "threat-hunter": (
            "Threat Hunter",
            "threat_hunt",
            "Threat-hunting analysis",
        ),
    }
    agent_label, job_type, job_label = labels.get(
        role,
        ("Unknown agent", "unknown", "Unknown analysis job"),
    )
    return {
        "agent_role": role or "unknown",
        "agent_label": agent_label,
        "job_type": job_type,
        "job_label": job_label,
    }


def decorate_llm_analysis_record(record: object, *, live: bool) -> dict:
    """Add display provenance while retaining the immutable raw audit fields."""
    decorated = dict(record) if isinstance(record, dict) else {}
    for key, value in llm_agent_execution_state(decorated).items():
        decorated.setdefault(key, value)
    if live:
        runtime = llm_runtime_model_state(decorated)
        if runtime.get("running"):
            decorated.update({
                "runtime_model_label": runtime.get("label") or "Unknown model",
                "phase_label": runtime.get("phase_label") or "Analysis",
            })
        else:
            decorated.update({
                "runtime_model_label": "No model running",
                "phase_label": "Idle",
            })
        return decorated
    # Completed rows retain the model/provider observed in the artifact. Treat
    # them as a legacy running record only for neutral route-label formatting.
    historical = dict(decorated)
    historical["status"] = "running"
    historical.pop("active_phase", None)
    runtime = llm_runtime_model_state(historical)
    model_observed = bool(
        str(decorated.get("model") or "").strip()
        or str(decorated.get("model_route") or "").strip()
    )
    decorated.update({
        "runtime_model_label": (
            runtime.get("label") or "Unknown model"
            if model_observed
            else "No model started"
        ),
        "phase_label": "Completed run",
    })
    return decorated


def read_llm_current_analysis() -> dict:
    queue_size = current_llm_queue_size()
    active_runs = read_active_llm_analyses()
    if active_runs:
        decorated_runs = [
            decorate_llm_analysis_record(record, live=True)
            for record in active_runs
        ]
        data = dict(decorated_runs[0])
        data.update({
            "ok": True,
            "status": "running",
            "queue_size": queue_size,
            "active_count": len(decorated_runs),
            "active_runs": decorated_runs,
        })
        if len(decorated_runs) > 1:
            runtimes = [llm_runtime_model_state(record) for record in decorated_runs]
            labels = [str(runtime.get("label") or "") for runtime in runtimes]
            providers = list(dict.fromkeys(
                str(runtime.get("provider") or "") for runtime in runtimes
                if runtime.get("provider")
            ))
            routes = [
                str(runtime.get("route") or "") for runtime in runtimes
                if runtime.get("route")
            ]
            data.update({
                "active_phase": "concurrent",
                "active_model": " + ".join(labels),
                "active_provider": " + ".join(providers),
                "active_model_route": " | ".join(routes),
                "runtime_model_label": " + ".join(labels),
                "phase_label": "Concurrent analyses",
                "agent_label": " + ".join(dict.fromkeys(
                    str(record.get("agent_label") or "")
                    for record in decorated_runs
                    if record.get("agent_label")
                )),
                "job_label": " + ".join(dict.fromkeys(
                    str(record.get("job_label") or "")
                    for record in decorated_runs
                    if record.get("job_label")
                )),
            })
        return data

    data = read_bounded_llm_analysis_record(SOC_ALERT_LLM_ANALYSIS_CURRENT_FILE)
    if not data:
        return decorate_llm_analysis_record({
            "ok": True,
            "status": "idle",
            "alert": {},
            "model": "n/a",
            "queue_size": queue_size,
        }, live=True)
    data = dict(data)
    data["ok"] = True
    data["queue_size"] = queue_size
    if data.get("status") == "running" and not llm_analysis_process_active(str(data.get("prompt_package") or "")):
        data["status"] = "idle"
        data["stale_running_record"] = True
    return decorate_llm_analysis_record(data, live=True)


def llm_runtime_model_state(current: object) -> dict:
    """Describe the model executing now without rewriting primary audit data."""
    if not isinstance(current, dict) or current.get("status") != "running":
        return {"running": False}
    has_phase_metadata = "active_phase" in current
    phase = str(current.get("active_phase") or "primary_analysis").strip().lower()
    if has_phase_metadata:
        route = str(current.get("active_model_route") or "").strip()
        model = str(current.get("active_model") or "").strip()
        provider_key = str(current.get("active_provider") or "").strip().lower()
        model_path = str(current.get("active_model_path") or "").strip().lower()
    else:
        # Rolling-deploy fallback for a runner that predates active-phase fields.
        route = str(current.get("model_route") or "").strip()
        model = str(current.get("model") or "").strip()
        provider_key = str(current.get("mode") or "").strip().lower()
        model_path = str(current.get("model_path") or "").strip().lower()

    provider = ""
    effort = ""
    if route.startswith("codex-cli:"):
        try:
            routed_model, effort = route.removeprefix("codex-cli:").rsplit(":", 1)
        except ValueError:
            routed_model = ""
        if routed_model:
            model = routed_model
        provider = "Codex CLI"
    elif route.startswith("hermes-agent:"):
        try:
            routed_model, effort = route.removeprefix("hermes-agent:").rsplit(":", 1)
        except ValueError:
            routed_model = ""
        if routed_model:
            model = routed_model
        provider = "Hermes Agent"
    elif route.startswith("openclaw:"):
        try:
            routed_model, effort = route.removeprefix("openclaw:").rsplit(":", 1)
        except ValueError:
            routed_model = ""
        if routed_model:
            model = routed_model
        provider = "OpenClaw"
    elif route.startswith("ollama:"):
        model = route.removeprefix("ollama:").strip() or model
        provider = "Ollama"
    elif provider_key in {"codex-cli", "gpt-cli"} or model_path == "frontier-codex-cli":
        provider = "Codex CLI"
    elif provider_key in {"hermes-agent", "openai-codex"} or model_path == "hermes-agent":
        provider = "Hermes Agent"
    elif provider_key == "openclaw" or model_path == "openclaw":
        provider = "OpenClaw"
    elif provider_key == "ollama" or model_path == "ollama":
        provider = "Ollama"

    if phase in {"preparing", "post_processing"} and not route and not model:
        phase_label = (
            "Preparing analysis"
            if phase == "preparing"
            else "Finalizing analysis"
        )
        return {
            "running": True,
            "phase": phase,
            "phase_label": phase_label,
            "route": "",
            "model": "",
            "provider": "",
            "label": "No model running",
            "detail": f"{phase_label} · No model running",
        }
    label = " · ".join(part for part in (provider, model) if part) or "Unknown model"
    if provider in {"Codex CLI", "Hermes Agent", "OpenClaw"} and effort:
        label += f" ({effort})"
    phase_label = {
        "preparing": "Preparing analysis",
        "second_opinion": "Second-opinion review",
        "disagreement_adjudication": "Disagreement adjudication",
        "live_follow_up": "Live-evidence follow-up",
        "primary_analysis": "Analyzing",
    }.get(phase, "Analyzing")
    return {
        "running": True,
        "phase": phase,
        "phase_label": phase_label,
        "route": route,
        "model": model,
        "provider": provider,
        "label": label,
        "detail": f"{phase_label} · Running: {label}",
    }


def merge_live_llm_activity(static_ai: object, current: object) -> dict:
    """Overlay current execution on the slower generated queue summary."""
    merged = dict(static_ai) if isinstance(static_ai, dict) else {}
    current_records = (
        [
            record for record in current.get("active_runs", [])
            if isinstance(record, dict)
        ]
        if isinstance(current, dict) and isinstance(current.get("active_runs"), list)
        else [current]
    )
    runtimes = [
        runtime
        for record in current_records
        if (runtime := llm_runtime_model_state(record)).get("running")
    ]
    if not runtimes:
        return merged
    counts = dict(merged.get("counts") or {}) if isinstance(merged.get("counts"), dict) else {}
    try:
        analyzing_count = int(counts.get("analyzing") or 0)
    except (TypeError, ValueError, OverflowError):
        analyzing_count = 0
    counts["analyzing"] = max(len(runtimes), analyzing_count)
    if len(runtimes) == 1:
        runtime = runtimes[0]
        detail = runtime["detail"]
        model = runtime["label"]
        provider = runtime["provider"]
        route = runtime["route"]
        phase = runtime["phase"]
    else:
        detail = (
            f"{len(runtimes)} analyses running · "
            + " | ".join(
                f"{runtime['phase_label']}: {runtime['label']}"
                for runtime in runtimes
            )
        )
        model = " + ".join(str(runtime["label"]) for runtime in runtimes)
        provider = " + ".join(dict.fromkeys(
            str(runtime["provider"]) for runtime in runtimes
            if runtime["provider"]
        ))
        route = " | ".join(
            str(runtime["route"]) for runtime in runtimes
            if runtime["route"]
        )
        phase = "concurrent"
    merged.update({
        "active": True,
        "label": str(merged.get("label") or "AI Alert Triage"),
        "detail": detail,
        "model": model,
        "provider": provider,
        "route": route,
        "phase": phase,
        "counts": counts,
    })
    return merged


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
    try:
        expected_pid = int(str(runner_pid or "").strip())
    except (TypeError, ValueError):
        expected_pid = 0
    if expected_pid > 0:
        for command in commands:
            parts = command.strip().split(maxsplit=1)
            if (
                len(parts) == 2
                and parts[0] == str(expected_pid)
                and "run-local-ai-analysis.py" in parts[1]
            ):
                return True
        return False
    if prompt_package:
        return any("run-local-ai-analysis.py" in command and prompt_package in command for command in commands)
    return any("run-local-ai-analysis.py" in command for command in commands)


LLM_ANALYSIS_COMBINED_HISTORY_LIMIT = 5000
LLM_AGENT_ACTIVITY_CACHE = ResponseCache(
    3.0,
    max_entries=1,
    lock_stripes=1,
)


def _llm_analysis_run_timestamp(value: object) -> float:
    text = str(value or "").strip()
    if not text:
        return 0.0
    try:
        parsed = dt.datetime.fromisoformat(text.replace("  ", "T", 1))
    except ValueError:
        return 0.0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.timestamp()


def _llm_primary_run_identity(record: object) -> tuple[str, str, float]:
    """Return a conservative fallback identity for pre-contract run records."""
    current = record if isinstance(record, dict) else {}
    alert = current.get("alert") if isinstance(current.get("alert"), dict) else {}
    alert_id = str(
        alert.get("primary_alert_id")
        or current.get("alert_id")
        or ""
    ).strip()
    role = str(current.get("agent_role") or "soc-analyst").strip().lower()
    role = role.replace("_", "-")
    timestamp = _llm_analysis_run_timestamp(
        current.get("finished_at")
        or current.get("generated_at")
        or current.get("started_at")
    )
    return alert_id, role, timestamp


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
    try:
        with soc_alert_db_connect() as conn:
            if not sqlite_table_exists(conn, "ai_analysis_runs"):
                return []
            run_columns = sqlite_table_columns(conn, "ai_analysis_runs")
            required = {"analysis_id", "alert_id", "generated_at"}
            if not required.issubset(run_columns):
                return []
            role_sql = (
                "COALESCE(NULLIF(TRIM(r.agent_role), ''), 'soc-analyst')"
                if "agent_role" in run_columns
                else "'soc-analyst'"
            )
            model_sql = "r.model" if "model" in run_columns else "NULL"
            model_path_sql = (
                "r.model_path" if "model_path" in run_columns else "NULL"
            )
            alert_columns = (
                sqlite_table_columns(conn, "alerts")
                if sqlite_table_exists(conn, "alerts")
                else set()
            )
            alert_projection = {
                "rule_name": (
                    "a.rule_name" if "rule_name" in alert_columns else "NULL"
                ),
                "source_ip": (
                    "a.source_ip" if "source_ip" in alert_columns else "NULL"
                ),
                "destination_ip": (
                    "a.destination_ip"
                    if "destination_ip" in alert_columns
                    else "NULL"
                ),
                "destination_port": (
                    "a.destination_port"
                    if "destination_port" in alert_columns
                    else "NULL"
                ),
                "seen_count": (
                    "a.seen_count" if "seen_count" in alert_columns else "1"
                ),
            }
            join_sql = (
                "LEFT JOIN alerts AS a ON a.alert_id = r.alert_id"
                if alert_columns
                else ""
            )
            rows = conn.execute(
                f"""
                SELECT r.analysis_id, r.alert_id, r.generated_at,
                       {role_sql} AS agent_role,
                       {model_sql} AS model, {model_path_sql} AS model_path,
                       {alert_projection["rule_name"]} AS rule_name,
                       {alert_projection["source_ip"]} AS source_ip,
                       {alert_projection["destination_ip"]} AS destination_ip,
                       {alert_projection["destination_port"]} AS destination_port,
                       {alert_projection["seen_count"]} AS seen_count
                FROM ai_analysis_runs AS r
                {join_sql}
                ORDER BY r.generated_at DESC, r.analysis_id DESC
                LIMIT ?
                """,
                (max(1, min(LLM_ANALYSIS_COMBINED_HISTORY_LIMIT, int(limit))),),
            ).fetchall()
    except (FileNotFoundError, sqlite3.Error, TypeError, ValueError):
        return []

    logs: list[dict] = []
    for raw in rows:
        row = dict(raw)
        analysis_id = str(row.get("analysis_id") or "").strip()
        alert_id = str(row.get("alert_id") or "").strip()
        generated_at = str(row.get("generated_at") or "").strip()
        try:
            alert_count = max(1, int(row.get("seen_count") or 1))
        except (TypeError, ValueError):
            alert_count = 1
        logs.append({
            "log_id": analysis_id,
            "analysis_id": analysis_id,
            "run_kind": "primary_analysis",
            "agent_role": row.get("agent_role") or "soc-analyst",
            "status": "success",
            "model": row.get("model"),
            "model_path": row.get("model_path"),
            "model_route": "",
            # SQLite records the committed completion time, not the start.
            # Display that observed timestamp without claiming a runtime.
            "started_at": generated_at,
            "finished_at": generated_at,
            "runtime_seconds": None,
            "telemetry_source": "analysis_run_database",
            "error": "Committed analysis record; host telemetry unavailable",
            "alert": {
                "primary_alert_id": alert_id,
                "rule_name": row.get("rule_name") or "Security Onion alert",
                "alert_count": alert_count,
                "source_ip": row.get("source_ip"),
                "destination_ip": row.get("destination_ip"),
                "destination_port": row.get("destination_port"),
            },
        })
    return logs


def reconcile_llm_primary_logs(
    telemetry_logs: list[dict],
    database_logs: list[dict],
) -> tuple[list[dict], int]:
    """Merge primary activity without double-counting legacy run identities."""
    merged = [dict(item) for item in telemetry_logs if isinstance(item, dict)]
    exact_ids: dict[str, int] = {}
    fallback: dict[tuple[str, str], list[tuple[float, int]]] = {}
    for index, item in enumerate(merged):
        run_id = str(
            item.get("analysis_id") or item.get("log_id") or ""
        ).strip()
        if run_id:
            exact_ids[run_id] = index
        alert_id, role, timestamp = _llm_primary_run_identity(item)
        if alert_id and timestamp:
            fallback.setdefault((alert_id, role), []).append((timestamp, index))

    def confirm_database_identity(index: int, database: dict) -> None:
        """Hydrate only provenance that SQLite authoritatively observed."""
        current = merged[index]
        if not str(current.get("agent_role") or "").strip():
            current["agent_role"] = (
                database.get("agent_role") or "soc-analyst"
            )
        if not str(current.get("analysis_id") or "").strip():
            current["analysis_id"] = database.get("analysis_id")
        current["database_confirmed"] = True

    recovered = 0
    for item in database_logs:
        if not isinstance(item, dict):
            continue
        run_id = str(
            item.get("analysis_id") or item.get("log_id") or ""
        ).strip()
        if run_id and run_id in exact_ids:
            confirm_database_identity(exact_ids[run_id], item)
            continue
        alert_id, role, timestamp = _llm_primary_run_identity(item)
        # Before the shared analysis-id contract, JSONL and SQLite used
        # different IDs. Alert, role, and a five-second completion window are
        # sufficiently strict to identify the same execution without merging
        # distinct reruns hours or days apart.
        matched_index = next(
            (
                index
                for observed, index in fallback.get((alert_id, role), ())
                if abs(timestamp - observed) <= 5.0
            ),
            None,
        ) if alert_id and timestamp else None
        if matched_index is not None:
            confirm_database_identity(matched_index, item)
            continue
        merged.append(dict(item))
        recovered += 1
        merged_index = len(merged) - 1
        if run_id:
            exact_ids[run_id] = merged_index
        if alert_id and timestamp:
            fallback.setdefault((alert_id, role), []).append(
                (timestamp, merged_index)
            )
    return merged, recovered


def _llm_reviewer_started_at(generated_at: object, runtime: object) -> str:
    """Derive the review start without inventing precision absent from SQLite."""
    text = str(generated_at or "").strip()
    try:
        seconds = max(0.0, float(runtime or 0))
        parsed = dt.datetime.fromisoformat(text.replace("  ", "T", 1))
    except (TypeError, ValueError, OverflowError):
        return text
    return (parsed - dt.timedelta(seconds=seconds)).isoformat(
        timespec="seconds",
    ).replace("T", "  ", 1)


LLM_PARENT_RUN_FIELDS = (
    "alert",
    "gpu_temperature_celsius_max",
    "gpu_utilization_percent_max",
    "gpu_percent_max",
    "cpu_temperature_celsius_max",
    "soc_temperature_celsius_max",
    "memory_used_percent_max",
    "power_watts_max",
    "cpu_used_percent_max",
    "pcap_total_size_bytes",
    "alert_context_size_bytes",
)


def hydrate_llm_reviewer_from_parent(
    reviewer: dict,
    parent: dict | None,
) -> None:
    """Attach collector-owned context from the reviewer's exact parent run."""
    if not isinstance(parent, dict):
        return
    for key in LLM_PARENT_RUN_FIELDS:
        if key in parent:
            reviewer[key] = parent.get(key)


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
    primary_by_id = {
        str(item.get("analysis_id") or item.get("log_id") or ""): item
        for item in primary_logs
        if isinstance(item, dict)
    }
    try:
        with soc_alert_db_connect() as conn:
            if not sqlite_table_exists(conn, "ai_second_opinion_runs"):
                return []
            columns = sqlite_table_columns(conn, "ai_second_opinion_runs")
            reviewer_error = (
                "reviewer_error"
                if "reviewer_error" in columns
                else "NULL AS reviewer_error"
            )
            rows = conn.execute(
                f"""
                SELECT analysis_id, alert_id, agent_role, trigger, status,
                       {reviewer_error}, reviewer_model, reviewer_model_path,
                       reviewer_outcome, reviewer_confidence, agreement,
                       material_disagreement, reviewer_runtime_seconds,
                       generated_at
                FROM ai_second_opinion_runs
                ORDER BY generated_at DESC, analysis_id DESC
                LIMIT ?
                """,
                (max(1, min(LLM_ANALYSIS_COMBINED_HISTORY_LIMIT, int(limit))),),
            ).fetchall()
    except (FileNotFoundError, sqlite3.Error, TypeError, ValueError):
        return []

    reviewer_logs: list[dict] = []
    for raw in rows:
        row = dict(raw)
        analysis_id = str(row.get("analysis_id") or "")
        parent = dict(primary_by_id.get(analysis_id) or {})
        status = str(row.get("status") or "unknown").strip().lower()
        error = str(row.get("reviewer_error") or "").strip()
        agreement = str(row.get("agreement") or "").strip()
        outcome = str(row.get("reviewer_outcome") or "").strip()
        detail_parts = [
            error,
            f"Agreement: {agreement.replace('_', ' ')}" if agreement else "",
            f"Outcome: {outcome.replace('_', ' ')}" if outcome else "",
        ]
        reviewer = {
            "log_id": f"{analysis_id}:second-opinion",
            "analysis_id": analysis_id,
            "parent_log_id": analysis_id,
            "run_kind": "second_opinion",
            "active_phase": "second_opinion",
            "phase_label": "Second-opinion review",
            "agent_role": row.get("agent_role"),
            "job_label": "Second-opinion review",
            "status": "success" if status == "completed" else status,
            "review_status": status,
            "error": " · ".join(part for part in detail_parts if part),
            "trigger": row.get("trigger"),
            "model": row.get("reviewer_model"),
            "model_path": row.get("reviewer_model_path"),
            "model_route": "",
            "mode": (
                "codex-cli"
                if row.get("reviewer_model_path") == "frontier-codex-cli"
                else row.get("reviewer_model_path")
            ),
            "runtime_seconds": row.get("reviewer_runtime_seconds"),
            "started_at": _llm_reviewer_started_at(
                row.get("generated_at"),
                row.get("reviewer_runtime_seconds"),
            ),
            "finished_at": row.get("generated_at"),
            "alert": parent.get("alert") or {
                "primary_alert_id": row.get("alert_id"),
                "rule_name": "Security Onion alert",
                "alert_count": 1,
            },
            "reviewer_outcome": outcome,
            "reviewer_confidence": row.get("reviewer_confidence"),
            "agreement": agreement,
            "material_disagreement": bool(row.get("material_disagreement")),
        }
        hydrate_llm_reviewer_from_parent(reviewer, parent)
        reviewer_logs.append(reviewer)
    return reviewer_logs


def read_llm_disagreement_adjudication_logs(
    primary_logs: list[dict],
    *,
    limit: int = LLM_ANALYSIS_COMBINED_HISTORY_LIMIT,
) -> list[dict]:
    """Return durable shadow adjudicator executions as distinct audit runs."""
    primary_by_id = {
        str(item.get("analysis_id") or item.get("log_id") or ""): item
        for item in primary_logs
        if isinstance(item, dict)
    }
    try:
        with soc_alert_db_connect() as conn:
            if not sqlite_table_exists(
                conn,
                "ai_disagreement_adjudication_runs",
            ):
                return []
            rows = conn.execute(
                """
                SELECT analysis_id, alert_id, agent_role, status, mode,
                       adjudicator_error, model_route, decision, confidence,
                       confidence_score, adjudicator_runtime_seconds,
                       human_adjudication_required, generated_at
                FROM ai_disagreement_adjudication_runs
                ORDER BY generated_at DESC, analysis_id DESC
                LIMIT ?
                """,
                (max(1, min(LLM_ANALYSIS_COMBINED_HISTORY_LIMIT, int(limit))),),
            ).fetchall()
    except (FileNotFoundError, sqlite3.Error, TypeError, ValueError):
        return []

    logs: list[dict] = []
    for raw in rows:
        row = dict(raw)
        analysis_id = str(row.get("analysis_id") or "")
        parent = dict(primary_by_id.get(analysis_id) or {})
        status = str(row.get("status") or "unknown").strip().lower()
        decision = str(row.get("decision") or "").strip()
        error = str(row.get("adjudicator_error") or "").strip()
        route = str(row.get("model_route") or "").strip()
        detail_parts = [
            error,
            f"Decision: {decision.replace('_', ' ')}" if decision else "",
            (
                "Human adjudication required"
                if row.get("human_adjudication_required")
                else ""
            ),
        ]
        mode = str(row.get("mode") or "shadow")
        if route.startswith("codex-cli:"):
            mode = "codex-cli"
        elif route.startswith("ollama:"):
            mode = "ollama"
        adjudicator = {
            "log_id": f"{analysis_id}:disagreement-adjudication",
            "analysis_id": analysis_id,
            "parent_log_id": analysis_id,
            "run_kind": "disagreement_adjudication",
            "active_phase": "disagreement_adjudication",
            "phase_label": "Disagreement adjudication",
            "agent_role": row.get("agent_role"),
            "job_label": "Disagreement adjudication",
            "status": "success" if status == "completed" else status,
            "review_status": status,
            "error": " · ".join(part for part in detail_parts if part),
            "model": route,
            "model_path": mode,
            "model_route": route,
            "mode": mode,
            "runtime_seconds": row.get("adjudicator_runtime_seconds"),
            "started_at": _llm_reviewer_started_at(
                row.get("generated_at"),
                row.get("adjudicator_runtime_seconds"),
            ),
            "finished_at": row.get("generated_at"),
            "alert": parent.get("alert") or {
                "primary_alert_id": row.get("alert_id"),
                "rule_name": "Security Onion alert",
                "alert_count": 1,
            },
            "adjudication_decision": decision,
            "adjudication_confidence": row.get("confidence"),
            "adjudication_confidence_score": row.get("confidence_score"),
            "human_adjudication_required": bool(
                row.get("human_adjudication_required")
            ),
        }
        hydrate_llm_reviewer_from_parent(adjudicator, parent)
        logs.append(adjudicator)
    return logs


def _llm_log_sort_timestamp(record: dict) -> float:
    for key in ("started_at", "finished_at"):
        text = str(record.get(key) or "").strip()
        if not text:
            continue
        try:
            parsed = dt.datetime.fromisoformat(text.replace("  ", "T", 1))
            return parsed.timestamp()
        except ValueError:
            continue
    return 0.0


def read_llm_agent_activity_snapshot() -> dict:
    """Build one bounded, role-complete history snapshot for pagination."""
    def compute() -> dict:
        telemetry_total, _, telemetry_logs = (
            SOC_ALERT_LLM_ANALYSIS_LOG_INDEX.page(
                page=1,
                limit=LLM_ANALYSIS_COMBINED_HISTORY_LIMIT,
            )
        )
        database_logs = read_llm_database_primary_logs()
        primary_logs, database_recovered_total = reconcile_llm_primary_logs(
            telemetry_logs,
            database_logs,
        )
        reviewer_logs = read_llm_second_opinion_logs(primary_logs)
        adjudication_logs = read_llm_disagreement_adjudication_logs(
            primary_logs,
        )
        combined = [*primary_logs, *reviewer_logs, *adjudication_logs]
        combined.sort(
            key=lambda record: (
                _llm_log_sort_timestamp(record),
                str(record.get("log_id") or ""),
            ),
            reverse=True,
        )
        agent_totals: dict[str, int] = {}
        for record in combined:
            role = str(
                record.get("agent_role") or "unknown"
            ).strip().lower()
            role = role.replace("_", "-") or "unknown"
            agent_totals[role] = agent_totals.get(role, 0) + 1
        return {
            "primary_logs": primary_logs,
            "reviewer_logs": reviewer_logs,
            "adjudication_logs": adjudication_logs,
            "combined": combined,
            "telemetry_total": telemetry_total,
            "database_recovered_total": database_recovered_total,
            "agent_totals": agent_totals,
            "history_truncated": (
                telemetry_total > len(telemetry_logs)
                or len(database_logs) >= LLM_ANALYSIS_COMBINED_HISTORY_LIMIT
                or len(reviewer_logs)
                >= LLM_ANALYSIS_COMBINED_HISTORY_LIMIT
                or len(adjudication_logs)
                >= LLM_ANALYSIS_COMBINED_HISTORY_LIMIT
            ),
        }

    return LLM_AGENT_ACTIVITY_CACHE.get_or_compute(
        "role-complete-history",
        compute,
    )


def llm_analysis_logs_response(query: dict[str, list[str]]) -> dict:
    requested_page = llm_analysis_log_page((query.get("page") or ["1"])[0])
    limit = llm_analysis_log_limit((query.get("limit") or ["25"])[0])
    activity = read_llm_agent_activity_snapshot()
    primary_logs = activity["primary_logs"]
    reviewer_logs = activity["reviewer_logs"]
    adjudication_logs = activity["adjudication_logs"]
    primary_total = len(primary_logs)
    total = primary_total + len(reviewer_logs) + len(adjudication_logs)
    total_pages = max(1, math.ceil(total / limit)) if total else 1
    page = min(requested_page, total_pages)
    combined = activity["combined"]
    start = (page - 1) * limit
    logs = combined[start:start + limit]
    return {
        "ok": True,
        "page": page,
        "limit": limit,
        "total": total,
        "primary_total": primary_total,
        "telemetry_total": activity["telemetry_total"],
        "database_recovered_total": activity[
            "database_recovered_total"
        ],
        "second_opinion_total": len(reviewer_logs),
        "disagreement_adjudication_total": len(adjudication_logs),
        "agent_totals": activity["agent_totals"],
        "history_truncated": activity["history_truncated"],
        "total_pages": total_pages,
        "logs": [
            decorate_llm_analysis_record(record, live=False)
            for record in logs
        ],
        "active_runs": [
            decorate_llm_analysis_record(record, live=True)
            for record in read_active_llm_analyses()
        ] if page == 1 else [],
    }


def update_soc_alert_status(payload: dict) -> tuple[bool, dict]:
    now = now_iso_utc()

    def valid_id(value: object) -> str:
        alert_id = str(value or "").strip()
        if re.fullmatch(r"[a-f0-9]{12}", alert_id):
            return alert_id
        return valid_soc_alert_store_id(alert_id)

    if isinstance(payload.get("statuses"), dict):
        # Historical dashboard builds used this endpoint to bulk-replace shared
        # analyst state from browser localStorage. That is unsafe now that
        # SQLite is the source of truth because an old tab can replay stale
        # acknowledgements/suppressions. Keep the route compatible, but treat
        # bulk browser state as read-only.
        return True, soc_alert_status_response()

    if isinstance(payload.get("acknowledged"), list):
        # Legacy dashboard builds sent the entire browser-local acknowledgement
        # list. Treat it as read-only for the same reason as the statuses map:
        # old tabs must never replace shared server-side analyst state.
        return True, soc_alert_status_response()

    alert_id = valid_id(payload.get("id"))
    if not alert_id:
        return False, {"ok": False, "error": "Invalid SOC alert id"}
    raw_status = str(payload.get("status") or "").strip().lower()
    if not raw_status:
        raw_status = "acknowledged" if bool(payload.get("acknowledged")) else "open"
    if raw_status not in {"open", "acknowledged", "suppressed"}:
        return False, {"ok": False, "error": "Invalid SOC alert status"}
    try:
        repeat_count = max(0, int(payload.get("repeat_count") or payload.get("acknowledged_count") or 0))
    except (TypeError, ValueError):
        repeat_count = 0
    if raw_status == "acknowledged" and repeat_count <= 0:
        repeat_count = current_soc_alert_group_repeat_count(alert_id)
    reason = str(payload.get("reason") or "").strip()[:140]
    request_payload = {
        "id": alert_id,
        "status": raw_status,
        "repeat_count": repeat_count,
        "reason": reason,
        "updated_at": now,
        "updated_by": "dashboard",
    }
    if not SOC_ALERT_STORE_API_URL:
        # Offline DR tests can explicitly disable the API. Production uses the
        # alert-store endpoint so only one process owns SQLite writes.
        if not SOC_ALERT_STORE_DIRECT_WRITE_ALLOWED:
            return False, {
                "ok": False,
                "error": (
                    "Direct SQLite writes are disabled; configure the "
                    "alert-store API or explicitly enter offline DR mode."
                ),
                "status": int(HTTPStatus.SERVICE_UNAVAILABLE),
            }
        if raw_status == "suppressed":
            try:
                with soc_alert_db_connect() as conn:
                    review = soc_alert_review_state_for_group(conn, alert_id)
            except (FileNotFoundError, sqlite3.Error):
                review = _soc_review_defaults()
            if review.get("final_review_status") in {
                "disputed_pending_human",
                "review_required_failed",
                "review_completed_not_authorized",
            }:
                return False, {
                    "ok": False,
                    "error": "Required independent review needs explicit analyst adjudication before suppression.",
                    "status": int(HTTPStatus.CONFLICT),
                }
        with SOC_ALERT_DB_WRITE_LOCK:
            write_soc_alert_status(alert_id, request_payload)
            return True, soc_alert_status_response()
    try:
        result = alert_store_post_json("/analyst-status", request_payload)
    except AlertStoreRequestError as exc:
        return False, {
            "ok": False,
            "error": f"Alert-store state update failed: {exc}",
            "status": exc.status_code,
        }
    return True, result


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

    if "cohort_id" not in payload and "dispatch_id" not in payload:
        return
    for field in (
        "release_id",
        "expected_assigned_route",
        "expected_reviewer_route",
        "reviewer_required",
    ):
        if field in payload:
            # Preserve exact values. The alert-store is the authoritative
            # validator and must see omissions, malformed routes, and false
            # reviewer flags rather than dashboard-normalized substitutes.
            request_payload[field] = payload[field]


def soc_alert_queue_analysis_response(group_id: str, payload: dict | None = None) -> tuple[int, dict]:
    """Record durable reanalysis intent; the worker builds fresh evidence later."""
    group_id = str(group_id or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{12}", group_id):
        return soc_alert_api_error("Invalid SOC alert group id")
    payload = payload if isinstance(payload, dict) else {}
    try:
        request_payload = {
            "group_id": group_id,
            "reason": str(payload.get("reason") or "SOC analyst requested fresh AI analysis")[:500],
            "requested_by": str(payload.get("requested_by") or "dashboard")[:100],
            "related_limit": max(1, min(500, int(payload.get("related_limit", 250)))),
            "pcap_analysis_limit": max(1, min(25, int(payload.get("pcap_analysis_limit", 8)))),
        }
        for identity_field in (
            "representative_alert_id",
            "stable_group_id",
            "stable_group_key",
            "cohort_id",
            "dispatch_id",
        ):
            if identity_field in payload:
                # Alert-store owns identity validation. Preserve the caller's
                # exact value so malformed or stale pins cannot be normalized
                # into a different, apparently valid dispatch.
                request_payload[identity_field] = payload[identity_field]
        _forward_controlled_dispatch_contract(payload, request_payload)
        data = alert_store_post_json(
            "/ai/request",
            request_payload,
            timeout=10.0,
        )
    except (TypeError, ValueError):
        return soc_alert_api_error("AI analysis queue limits must be integers", 400)
    except AlertStoreRequestError as exc:
        return soc_alert_api_error(
            f"Alert-store AI queue request failed: {exc}",
            exc.status_code,
        )
    except RuntimeError as exc:
        return soc_alert_api_error(f"Alert-store AI queue request failed: {exc}", 503)
    return 202, {
        **data,
        "ai_status_key": "queued",
        "ai_status_label": "Queued",
        "ai_status_detail": f"Manual SOC Analyst reanalysis queued at {now_iso_local()}",
    }


def soc_alert_escalate_response(group_id: str, payload: dict | None = None) -> tuple[int, dict]:
    """Create or refresh one durable Incident Response case for an alert group."""
    group_id = str(group_id or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{12}", group_id):
        return soc_alert_api_error("Invalid SOC alert group id")
    payload = payload if isinstance(payload, dict) else {}
    try:
        request_payload = {
            "group_id": group_id,
            "reason": str(payload.get("reason") or "Escalated from SOC Alerts for incident response")[:1000],
            "requested_by": str(payload.get("requested_by") or "dashboard")[:100],
            "related_limit": max(1, min(500, int(payload.get("related_limit", 250)))),
            "pcap_analysis_limit": max(1, min(25, int(payload.get("pcap_analysis_limit", 25)))),
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
        data = alert_store_post_json(
            "/incidents/escalate",
            request_payload,
            timeout=10.0,
        )
    except (TypeError, ValueError):
        return soc_alert_api_error("Incident response queue limits must be integers", 400)
    except AlertStoreRequestError as exc:
        return soc_alert_api_error(
            f"Incident response escalation failed: {exc}",
            exc.status_code,
        )
    except RuntimeError as exc:
        return soc_alert_api_error(f"Incident response escalation failed: {exc}", 503)
    return 202, {
        **data,
        "agent_status": "queued",
        "agent_status_label": "Queued",
        "detail": f"Incident Responder analysis queued at {now_iso_local()}",
    }


SOC_ANALYST_ADJUDICATION_OUTCOMES = {
    "true_positive_malicious",
    "true_positive_suspicious",
    "true_positive_authorized_benign",
    "false_positive_logic_rule",
    "false_positive_data_parser",
    "false_positive_bad_intel_ioc",
    "false_negative",
    "duplicate",
    "informational_no_action",
    "inconclusive",
}
SOC_ANALYST_EVENT_STATUSES = {"observed", "not_observed", "unknown"}
SOC_ANALYST_DETECTION_VALIDITIES = {
    "matched_intent",
    "logic_error",
    "parser_error",
    "intel_error",
    "not_applicable",
    "unknown",
}
SOC_ANALYST_ACTIVITY_DISPOSITIONS = {
    "malicious",
    "suspicious",
    "authorized_benign",
    "benign",
    "unknown",
}
SOC_ANALYST_HANDLING_VALUES = {
    "contain",
    "escalate",
    "investigate",
    "monitor",
    "no_action",
}


def _soc_legacy_verdict_factors(outcome: str) -> dict[str, str | None]:
    """Return the canonical factored form used by the analysis runner."""
    handling_for_risk = "investigate"
    mapping: dict[str, tuple[str, str, str, str]] = {
        "true_positive_malicious": (
            "observed", "matched_intent", "malicious", "contain",
        ),
        "true_positive_suspicious": (
            "observed", "matched_intent", "suspicious", handling_for_risk,
        ),
        "true_positive_authorized_benign": (
            "observed", "matched_intent", "authorized_benign", "no_action",
        ),
        "false_positive_logic_rule": (
            "observed", "logic_error", "unknown", "monitor",
        ),
        "false_positive_data_parser": (
            "unknown", "parser_error", "unknown", "investigate",
        ),
        "false_positive_bad_intel_ioc": (
            "observed", "intel_error", "unknown", "monitor",
        ),
        "false_negative": (
            "observed", "not_applicable", "malicious", "escalate",
        ),
        "duplicate": ("observed", "unknown", "unknown", "no_action"),
        "informational_no_action": (
            "observed", "not_applicable", "benign", "no_action",
        ),
        "inconclusive": ("unknown", "unknown", "unknown", "investigate"),
    }
    event_status, detection_validity, activity_disposition, handling = mapping[
        outcome
    ]
    return {
        "event_status": event_status,
        "detection_validity": detection_validity,
        "activity_disposition": activity_disposition,
        "handling": handling,
        "duplicate_of": None,
    }


def _soc_derive_legacy_detection_outcome(
    factors: dict[str, str | None],
) -> str:
    """Mirror the runner's deterministic compatibility-outcome derivation."""
    duplicate_of = str(factors.get("duplicate_of") or "").strip()
    validity = str(factors.get("detection_validity") or "unknown")
    event_status = str(factors.get("event_status") or "unknown")
    disposition = str(factors.get("activity_disposition") or "unknown")
    handling = str(factors.get("handling") or "investigate")
    if duplicate_of:
        return "duplicate"
    if validity == "parser_error":
        return "false_positive_data_parser"
    if validity == "logic_error":
        return "false_positive_logic_rule"
    if validity == "intel_error":
        return "false_positive_bad_intel_ioc"
    if validity == "matched_intent" and event_status == "observed":
        if disposition == "malicious":
            return "true_positive_malicious"
        if disposition == "suspicious":
            return "true_positive_suspicious"
        if disposition == "authorized_benign":
            return "true_positive_authorized_benign"
        if disposition == "benign" and handling == "no_action":
            return "informational_no_action"
    if validity == "not_applicable" and event_status == "observed":
        if disposition == "malicious":
            return "false_negative"
        if disposition in {"benign", "authorized_benign"} and handling == "no_action":
            return "informational_no_action"
    return "inconclusive"


def _soc_adjudication_verdict_contradictions(
    outcome: str,
    explicit_factors: dict[str, str | None],
) -> list[str]:
    """Reject impossible combinations before they become durable labels."""
    supplied = {
        key: value
        for key, value in explicit_factors.items()
        if value not in (None, "")
    }
    if not supplied:
        return []
    factors = _soc_legacy_verdict_factors(outcome)
    factors.update(supplied)
    derived = _soc_derive_legacy_detection_outcome(factors)
    contradictions: list[str] = []
    if derived != outcome:
        contradictions.append(
            f"factored verdict derives {derived}, not {outcome}"
        )
    event_status = str(factors["event_status"])
    validity = str(factors["detection_validity"])
    disposition = str(factors["activity_disposition"])
    handling = str(factors["handling"])
    duplicate_of = str(factors.get("duplicate_of") or "").strip()
    if event_status == "not_observed" and validity == "matched_intent":
        contradictions.append(
            "an unobserved event cannot be a validated detection-intent match"
        )
    if disposition == "malicious" and handling in {"monitor", "no_action"}:
        contradictions.append(
            "malicious activity cannot use monitor/no_action handling"
        )
    if disposition in {"authorized_benign", "benign"} and handling == "contain":
        contradictions.append("benign or authorized activity cannot use contain handling")
    if duplicate_of and handling in {"contain", "escalate"}:
        contradictions.append(
            "a duplicate record cannot independently authorize containment or escalation"
        )
    if outcome.startswith("false_positive_"):
        if disposition in {"malicious", "suspicious"}:
            contradictions.append(
                "a false-positive label cannot authoritatively classify the activity as malicious or suspicious"
            )
        if handling in {"contain", "escalate"}:
            contradictions.append(
                "a false-positive label cannot independently authorize containment or escalation"
            )
    return contradictions


def normalize_soc_adjudication_payload(
    payload: dict | None,
    *,
    group_id: str,
    case_id: str = "",
) -> tuple[bool, dict]:
    """Validate bounded human review fields before crossing the write boundary."""
    payload = payload if isinstance(payload, dict) else {}
    group_id = str(group_id or "").strip().lower()
    case_id = str(case_id or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{12}", group_id):
        return False, {"ok": False, "error": "Invalid SOC alert group id"}
    if case_id and not re.fullmatch(r"ir-[a-z0-9_-]{1,64}", case_id):
        return False, {"ok": False, "error": "Invalid incident case id"}
    outcome = str(payload.get("outcome_override") or "").strip().lower()
    confidence = str(payload.get("confidence") or "").strip().lower()
    rationale = str(payload.get("rationale") or "").strip()[:4000]
    evidence_gap = str(payload.get("evidence_gap") or "").strip()[:4000]
    next_action = str(payload.get("next_action") or "").strip()[:4000]
    reviewer = str(payload.get("reviewer") or "").strip()[:100]
    resolution_reason = str(payload.get("case_resolution_reason") or "").strip()[:2000]
    if "resolve_case" in payload and not isinstance(payload.get("resolve_case"), bool):
        return False, {
            "ok": False,
            "error": "resolve_case must be a JSON boolean.",
        }
    resolve_case = payload.get("resolve_case") is True
    analysis_id = str(payload.get("analysis_id") or "").strip()[:160]
    factored_values: dict[str, str | None] = {}
    for field, allowed in (
        ("event_status", SOC_ANALYST_EVENT_STATUSES),
        ("detection_validity", SOC_ANALYST_DETECTION_VALIDITIES),
        ("activity_disposition", SOC_ANALYST_ACTIVITY_DISPOSITIONS),
        ("handling", SOC_ANALYST_HANDLING_VALUES),
    ):
        value = str(payload.get(field) or "").strip().lower()
        if value and value not in allowed:
            return False, {
                "ok": False,
                "error": f"Select a valid {field.replace('_', ' ')}.",
            }
        factored_values[field] = value or None
    duplicate_value = payload.get("duplicate_of")
    if duplicate_value is None:
        duplicate_of = None
    elif isinstance(duplicate_value, str):
        duplicate_of = duplicate_value.strip()[:256]
        if not duplicate_of:
            return False, {
                "ok": False,
                "error": "duplicate_of must be a non-empty string identifier or null.",
            }
    else:
        return False, {
            "ok": False,
            "error": "duplicate_of must be a string identifier or null.",
        }
    if outcome not in SOC_ANALYST_ADJUDICATION_OUTCOMES:
        return False, {"ok": False, "error": "Select a valid analyst outcome."}
    if confidence not in {"low", "medium", "high"}:
        return False, {"ok": False, "error": "Select low, medium, or high confidence."}
    if not rationale or not reviewer:
        return False, {"ok": False, "error": "Reviewer and rationale are required."}
    contradictions = _soc_adjudication_verdict_contradictions(
        outcome,
        {**factored_values, "duplicate_of": duplicate_of},
    )
    if contradictions:
        return False, {
            "ok": False,
            "error": (
                "Analyst outcome conflicts with the explicit verdict factors: "
                + "; ".join(contradictions)
            )[:1000],
        }
    if resolve_case and (not case_id or not resolution_reason):
        return False, {
            "ok": False,
            "error": "A case resolution reason is required when resolving a case.",
        }
    return True, {
        "group_id": group_id,
        "case_id": case_id or None,
        "analysis_id": analysis_id,
        "outcome_override": outcome,
        "confidence": confidence,
        "rationale": rationale,
        "evidence_gap": evidence_gap,
        "next_action": next_action,
        "reviewer": reviewer,
        **factored_values,
        "duplicate_of": duplicate_of,
        "resolve_case": resolve_case,
        "case_resolution_reason": resolution_reason,
    }


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


def soc_adjudication_history_response(
    group_id: str,
    *,
    case_id: str = "",
    limit: int = 25,
) -> tuple[int, dict]:
    group_id = str(group_id or "").strip().lower()
    case_id = str(case_id or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{12}", group_id):
        return soc_alert_api_error("Invalid SOC alert group id")
    if case_id and not re.fullmatch(r"ir-[a-z0-9_-]{1,64}", case_id):
        return soc_alert_api_error("Invalid incident case id")
    limit = max(1, min(100, int(limit or 25)))
    try:
        with soc_alert_db_connect() as conn:
            if not sqlite_table_exists(conn, "analyst_adjudications"):
                return 200, {"ok": True, "review": _soc_review_defaults(), "history": []}
            sql = """
                SELECT adjudication_id, dashboard_group_id, stable_group_id,
                       case_id, analysis_id, outcome_override, confidence,
                       rationale, evidence_gap, next_action, reviewer,
                       event_status, detection_validity, activity_disposition,
                       handling, duplicate_of,
                       case_resolution_reason, created_at
                FROM analyst_adjudications
            """
            if case_id:
                sql += " WHERE case_id = ?"
                arguments: list[object] = [case_id]
            else:
                stable_group_id = ""
                if sqlite_table_exists(conn, "alert_group_alias"):
                    row = conn.execute(
                        "SELECT stable_group_id FROM alert_group_alias "
                        "WHERE legacy_group_id = ?",
                        (group_id,),
                    ).fetchone()
                    stable_group_id = str(row["stable_group_id"] or "") if row else ""
                if (
                    not stable_group_id
                    and sqlite_table_exists(conn, "alert_group_summary")
                    and "stable_group_id" in sqlite_table_columns(conn, "alerts")
                ):
                    row = conn.execute(
                        """
                        SELECT a.stable_group_id
                        FROM alert_group_summary AS g
                        JOIN alerts AS a ON a.alert_id = g.representative_alert_id
                        WHERE g.group_id = ?
                        """,
                        (group_id,),
                    ).fetchone()
                    stable_group_id = str(row["stable_group_id"] or "") if row else ""
                if stable_group_id:
                    sql += " WHERE stable_group_id = ?"
                    arguments = [stable_group_id]
                else:
                    sql += " WHERE dashboard_group_id = ?"
                    arguments = [group_id]
            sql += " ORDER BY created_at DESC, rowid DESC LIMIT ?"
            arguments.append(limit)
            history = [dict(row) for row in conn.execute(sql, arguments).fetchall()]
            review = soc_alert_review_state_for_group(conn, group_id)
            if case_id and sqlite_table_exists(conn, "incident_response_cases"):
                case_row = conn.execute(
                    "SELECT * FROM incident_response_cases WHERE case_id = ?",
                    (case_id,),
                ).fetchone()
                if case_row:
                    case = dict(case_row)
                    analysis = soc_incident_current_analysis(conn, case)
                    response = _soc_review_json(analysis.get("response_json"))
                    review = soc_incident_review_state(
                        conn,
                        case,
                        analysis,
                        response,
                    )
    except (FileNotFoundError, sqlite3.Error) as exc:
        return soc_alert_api_error(f"Analyst review history unavailable: {exc}", 503)
    return 200, {"ok": True, "review": review, "history": history}


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
    try:
        request = parse_incident_list_request(
            query,
            max_per_page=SOC_ALERT_API_MAX_LIMIT,
        )
    except IncidentQueryError as exc:
        return soc_alert_api_error(str(exc))
    try:
        with soc_alert_db_connect() as conn:
            if not incident_schema_ready(conn):
                return 200, empty_incident_page(request)
            records = load_incident_list_records(conn, request)
            incident_inventory, incident_inventory_error = load_asset_inventory_data()
            incidents = compose_incident_list_rows(
                conn,
                records,
                incident_inventory,
                incident_inventory_error,
                _soc_review_defaults(),
                INCIDENT_ROW_CALLBACKS,
            )
    except (FileNotFoundError, sqlite3.Error) as exc:
        return soc_alert_api_error(f"Incident Response data unavailable: {exc}", 503)
    return 200, {
        "ok": True,
        "incidents": incidents,
        "page": records.page,
        "per_page": request.per_page,
        "total": records.total,
        "pages": records.pages,
        "status_counts": records.status_counts,
        "agent_status_counts": records.agent_status_counts,
        "schema_ready": True,
        "sort": request.sort,
        "direction": request.direction,
        "asset_inventory_status": (
            "invalid"
            if incident_inventory_error
            else str(incident_inventory.get("inventory_status") or "loaded")
        ),
    }


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


def soc_incident_detail_response(case_id: str) -> tuple[int, dict]:
    """Return one bounded IR report, its exact query audit, and prior SOC analysis."""
    case_id = str(case_id or "").strip().lower()
    if not re.fullmatch(r"ir-[a-z0-9_-]{1,64}", case_id):
        return soc_alert_api_error("Invalid incident case id")
    try:
        with soc_alert_db_connect() as conn:
            records = load_incident_detail_records(conn, case_id)
    except IncidentSchemaUnavailable:
        return soc_alert_api_error("Incident Response schema is unavailable", 503)
    except IncidentCaseNotFound:
        return soc_alert_api_error("Incident case not found", 404)
    except (FileNotFoundError, sqlite3.Error) as exc:
        return soc_alert_api_error(f"Incident Response detail unavailable: {exc}", 503)

    response = parse_analysis_response(records.analysis)
    prior_response = parse_analysis_response(records.prior_analysis)
    review = compose_incident_review_state(
        records.case,
        records.analysis,
        response,
        records.review.evidence_updated_at,
        records.review.reviewer,
        records.review.adjudication,
        _soc_review_defaults(),
        INCIDENT_ROW_CALLBACKS,
    )
    incident_html, query_count = render_incident_response_report_html(
        records.case,
        response,
        records.analysis,
        review,
    )
    prior_html = render_prior_soc_analysis_html(
        prior_response, records.prior_analysis
    )
    return 200, compose_incident_detail_payload(
        case_id,
        records.case,
        response,
        review,
        incident_html,
        prior_html,
        query_count,
    )


def soc_alert_row_filter_status(row: sqlite3.Row) -> str:
    return str(row["filter_status"] or "accepted").strip().lower()


def soc_alert_row_matches_analyst_status(row: sqlite3.Row, group_id: str, statuses: dict, analyst_status: str) -> bool:
    current_status = (statuses.get(group_id, {}) or {}).get("status", "open") if isinstance(statuses, dict) else "open"
    filter_status = soc_alert_row_filter_status(row)
    if analyst_status in {"open", "new"}:
        return current_status == "open" and filter_status != "suppressed"
    if analyst_status == "suppressed":
        return current_status == "suppressed" or filter_status == "suppressed"
    if analyst_status == "acknowledged":
        return current_status == "acknowledged"
    return True


def soc_alert_status_bucket_counts(rows: list[sqlite3.Row], statuses: dict) -> dict[str, int]:
    def group_id_for_row(row: sqlite3.Row) -> str:
        group_key = row["group_key"] if "group_key" in row.keys() else ""
        return row["group_id"] if "group_id" in row.keys() and row["group_id"] else soc_alert_group_id(group_key)

    return soc_alert_api.status_bucket_counts(rows, statuses, group_id_for_row)


def soc_alert_top_endpoint_metrics(rows: list[sqlite3.Row]) -> dict[str, str]:
    return soc_alert_api.top_endpoint_metrics(rows)


def soc_alert_group_id_for_query_row(row: sqlite3.Row | dict) -> str:
    keys = row.keys()
    if "group_id" in keys and row["group_id"]:
        return str(row["group_id"])
    return soc_alert_group_id(row["group_key"])


def soc_alert_filter_group_rows(
    rows: list[sqlite3.Row],
    statuses: dict,
    analyst_status: str,
    cursor_seen: str,
    cursor_id: str,
) -> list[sqlite3.Row]:
    filtered_rows: list[sqlite3.Row] = []
    for row in rows:
        group_id = soc_alert_group_id_for_query_row(row)
        if not soc_alert_row_matches_analyst_status(row, group_id, statuses, analyst_status):
            continue
        if cursor_seen and cursor_id:
            group_last_seen = row["group_last_seen"] or row["last_seen"] or ""
            if not (group_last_seen < cursor_seen or (group_last_seen == cursor_seen and group_id < cursor_id)):
                continue
        filtered_rows.append(row)
    return filtered_rows


def soc_alert_enriched_page_rows(page_rows: list[sqlite3.Row]) -> list[sqlite3.Row | dict]:
    if not page_rows:
        return []
    try:
        with soc_alert_db_connect() as conn:
            enrichment_by_group = soc_alert_group_enrichment_json_map(
                conn,
                [row["group_key"] for row in page_rows if "group_key" in row.keys()],
            )
            return [
                {
                    **dict(row),
                    "enrichment_json": (
                        dict(row).get("enrichment_json")
                        or enrichment_by_group.get(str(row["group_key"] or ""), "")
                    ),
                }
                for row in page_rows
            ]
    except Exception:
        return [dict(row) for row in page_rows]


def soc_alert_group_next_cursor(filtered_rows: list[sqlite3.Row], page_rows: list[sqlite3.Row | dict], offset: int, limit: int) -> str | None:
    if len(filtered_rows) <= offset + limit or not page_rows:
        return None
    tail = page_rows[-1]
    group_id = soc_alert_group_id_for_query_row(tail)
    return f"{tail['group_last_seen'] or tail['last_seen']}|{group_id}"


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
    if excluded_group_ids:
        rows = [
            row for row in rows
            if soc_alert_group_id_for_query_row(row) not in excluded_group_ids
        ]
    statuses = load_soc_alert_statuses()
    status_counts = soc_alert_status_bucket_counts(rows, statuses)
    # Active-card metrics describe work still requiring analyst action. Compute
    # them from the complete filtered query before applying the selected analyst
    # bucket, cursor, or page slice so UI pagination can never change the totals.
    active_rows = soc_alert_filter_group_rows(rows, statuses, "open", "", "")
    active_severity_summary = soc_alert_visible_severity_summary(active_rows)
    filtered_rows = soc_alert_filter_group_rows(rows, statuses, analyst_status, cursor_seen, cursor_id)
    severity_summary = soc_alert_visible_severity_summary(filtered_rows)
    total_matching = len(filtered_rows)
    total_pages = max(1, (total_matching + limit - 1) // limit)
    current_page = min(requested_page, total_pages)
    offset = (current_page - 1) * limit
    page_rows = soc_alert_enriched_page_rows(filtered_rows[offset:offset + limit])
    return SocAlertQuerySnapshot(
        statuses=statuses,
        status_counts=status_counts,
        active_total=len(active_rows),
        active_severity_counts=active_severity_summary["counts"],
        active_highest_severity=active_severity_summary["highest"],
        severity_counts=severity_summary["counts"],
        highest_severity=severity_summary["highest"],
        top_endpoints=soc_alert_top_endpoint_metrics(filtered_rows),
        filtered_rows=filtered_rows,
        page_rows=page_rows,
        total_matching=total_matching,
        total_pages=total_pages,
        current_page=current_page,
        offset=offset,
        next_cursor=soc_alert_group_next_cursor(filtered_rows, page_rows, offset, limit),
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
    where = " where last_seen >= ?" if since else ""
    args = [since] if since else []
    group_expr = soc_alert_group_key_sql()
    metrics_source = "sqlite"
    try:
        with soc_alert_db_connect() as conn:
            total = conn.execute(f"select count(*) from alerts{where}", args).fetchone()[0]
            latest = conn.execute(f"select max(last_seen) from alerts{where}", args).fetchone()[0]
            if soc_alert_group_summary_available(conn):
                metrics_source = "sqlite-summary"
                summary_where = " where last_seen >= ?" if since else ""
                grouped_rows = conn.execute(
                    f"""
                    SELECT group_id, group_key, raw_alert_count, total_seen_count,
                           last_seen, filter_status
                    FROM alert_group_summary
                    {summary_where}
                    """,
                    args,
                ).fetchall()
            else:
                grouped_rows = conn.execute(
                    f"""
                    SELECT {group_expr} AS group_key,
                           COUNT(*) AS raw_alert_count,
                           COALESCE(SUM(MAX(1, COALESCE(seen_count, 1))), 0) AS total_seen_count,
                           MAX(last_seen) AS last_seen,
                           COALESCE(NULLIF(filter_status, ''), 'accepted') AS filter_status
                    FROM alerts
                    {where}
                    GROUP BY group_key, filter_status
                    """,
                    args,
                ).fetchall()
            manually_escalated_group_ids = soc_alert_manually_escalated_group_ids(conn)
            grouped_rows = [
                row for row in grouped_rows
                if soc_alert_group_id_for_query_row(row) not in manually_escalated_group_ids
            ]
            by_filter = {r[0] or "accepted": r[1] for r in conn.execute(f"select coalesce(filter_status, 'accepted'), count(*) from alerts{where} group by coalesce(filter_status, 'accepted')", args)}
            by_level = {r[0] or "unknown": r[1] for r in conn.execute(f"select coalesce(triage_level, severity_label, 'unknown'), count(*) from alerts{where} group by coalesce(triage_level, severity_label, 'unknown')", args)}
            top_rules = [dict(rule_name=r[0] or "unknown", count=r[1]) for r in conn.execute(f"select coalesce(rule_name, 'unknown'), count(*) from alerts{where} group by coalesce(rule_name, 'unknown') order by count(*) desc limit 10", args)]
            suppression_windows = conn.execute("select count(*), coalesce(sum(suppressed_count), 0), coalesce(sum(escalated_count), 0) from suppression_log").fetchone()
    except Exception as e:
        return soc_alert_api_error(str(e), 503)
    statuses = load_soc_alert_statuses()
    by_analyst_status = soc_alert_status_bucket_counts(grouped_rows, statuses)
    grouped_observations = 0
    for row in grouped_rows:
        grouped_observations += max(int(row["raw_alert_count"] or 0), int(row["total_seen_count"] or 0))
    return 200, {
        "ok": True,
        "source": metrics_source,
        "mode": "grouped",
        "since": since or None,
        "total": total,
        "grouped_total": len(grouped_rows),
        "grouped_observations": grouped_observations,
        "pcap_ingest_size_bytes": directory_size_bytes(SOC_ALERT_PCAP_ARTIFACT_DIR),
        "latest_seen": latest,
        "by_filter_status": by_filter,
        "by_analyst_status": by_analyst_status,
        "by_level": by_level,
        "top_rules": top_rules,
        "suppression_log": {
            "windows": suppression_windows[0],
            "suppressed_count": suppression_windows[1],
            "escalated_count": suppression_windows[2],
        },
    }


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


def _revision_digest(value: object) -> str:
    """Return an opaque, deterministic live-update token."""
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _bounded_file_revision(path: Path, maximum_bytes: int) -> str:
    """Fingerprint file identity without exposing its path or contents."""
    try:
        metadata = path.stat()
        if not path.is_file() or metadata.st_size > maximum_bytes:
            return _revision_digest(("invalid",))
        return _revision_digest((metadata.st_mtime_ns, metadata.st_size))
    except FileNotFoundError:
        return _revision_digest(("missing",))
    except OSError:
        return _revision_digest(("unavailable",))


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


def _revision_rows(
    conn: sqlite3.Connection,
    table: str,
    columns: tuple[str, ...],
    *,
    where_sql: str = "",
    arguments: tuple[object, ...] = (),
    order_sql: str = "",
    limit: int | None = None,
) -> list[dict[str, object]]:
    """Read a schema-tolerant, bounded table slice for revision hashing."""
    if not sqlite_table_exists(conn, table):
        return []
    available = sqlite_table_columns(conn, table)
    selected = [column for column in columns if column in available]
    if not selected:
        return []
    query = f"SELECT {', '.join(selected)} FROM {table}"
    if where_sql:
        query += f" WHERE {where_sql}"
    if order_sql:
        query += f" ORDER BY {order_sql}"
    query_arguments = list(arguments)
    if limit is not None:
        query += " LIMIT ?"
        query_arguments.append(limit)
    return [dict(row) for row in conn.execute(query, query_arguments).fetchall()]


def incident_response_live_revision() -> str:
    """Fingerprint only records capable of changing the Incident Responder UI."""
    try:
        with soc_alert_db_connect() as conn:
            cases = _revision_rows(
                conn,
                "incident_response_cases",
                (
                    "case_id", "group_id", "dashboard_group_id",
                    "representative_alert_id", "status", "agent_status",
                    "escalated_at", "updated_at", "latest_analysis_id",
                    "latest_model", "latest_generated_at", "latest_error",
                    "resolution_reason", "resolved_at", "resolved_by",
                ),
                order_sql="case_id",
            )
            dashboard_group_ids = tuple(
                str(row["dashboard_group_id"])
                for row in cases
                if row.get("dashboard_group_id")
            )
            representative_alert_ids = tuple(
                str(row["representative_alert_id"])
                for row in cases
                if row.get("representative_alert_id")
            )
            analysis_ids = tuple(
                str(row["latest_analysis_id"])
                for row in cases
                if row.get("latest_analysis_id")
            )
            case_ids = tuple(
                str(row["case_id"]) for row in cases if row.get("case_id")
            )

            def related_rows(
                table: str,
                columns: tuple[str, ...],
                key: str,
                values: tuple[str, ...],
            ) -> list[dict[str, object]]:
                if not values:
                    return []
                placeholders = ",".join("?" for _ in values)
                return _revision_rows(
                    conn,
                    table,
                    columns,
                    where_sql=f"{key} IN ({placeholders})",
                    arguments=values,
                    order_sql=key,
                )

            state: dict[str, object] = {"cases": cases}
            state["groups"] = related_rows(
                "alert_group_summary",
                (
                    "group_id", "rule_name", "severity", "severity_label",
                    "triage_level", "source_ip", "destination_ip",
                    "destination_port", "raw_alert_count", "total_seen_count",
                    "first_seen", "last_seen",
                ),
                "group_id",
                dashboard_group_ids,
            )
            state["alerts"] = related_rows(
                "alerts",
                (
                    "alert_id", "rule_name", "severity", "severity_label",
                    "triage_level", "source_ip", "destination_ip",
                    "destination_port", "seen_count", "first_seen", "last_seen",
                ),
                "alert_id",
                representative_alert_ids,
            )
            state["analyses"] = related_rows(
                "ai_analysis_runs",
                (
                    "analysis_id", "generated_at", "model", "detection_outcome",
                    "confidence", "evidence_hash", "response_json",
                ),
                "analysis_id",
                analysis_ids,
            )
            state["reviews"] = related_rows(
                "ai_second_opinion_runs",
                (
                    "analysis_id", "status", "reviewer_outcome",
                    "reviewer_confidence", "agreement", "material_disagreement",
                    "disputed_fields_json", "generated_at",
                ),
                "analysis_id",
                analysis_ids,
            )
            state["adjudications"] = related_rows(
                "analyst_adjudications",
                (
                    "case_id", "analysis_id", "outcome_override", "confidence",
                    "event_status", "detection_validity", "activity_disposition",
                    "handling", "case_resolution_reason", "created_at",
                ),
                "case_id",
                case_ids,
            )
            latest_runs = _revision_rows(
                conn,
                "incident_reanalysis_runs",
                (
                    "run_id", "release_id", "scope", "status", "total_count",
                    "created_at", "updated_at", "completed_at",
                ),
                order_sql="created_at DESC",
                limit=1,
            )
            state["reanalysis_runs"] = latest_runs
            if latest_runs:
                run_id = str(latest_runs[0].get("run_id") or "")
                state["reanalysis_cases"] = related_rows(
                    "incident_reanalysis_run_cases",
                    (
                        "run_id", "case_id", "status", "skip_reason",
                        "latest_error", "analysis_id", "result_generated_at",
                        "updated_at",
                    ),
                    "run_id",
                    (run_id,),
                )
            return _revision_digest(state)
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


class PortalHandler(BaseHTTPRequestHandler):
    server_version = "ArronReportPortal/1.0"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), fmt % args))

    def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8", extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str, extra: dict[str, str] | None = None, status: HTTPStatus = HTTPStatus.FOUND) -> None:
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()

    def _serve_file(self, target: Path) -> None:
        if not target.is_file():
            return self._send(HTTPStatus.NOT_FOUND, b"Asset not found", "text/plain; charset=utf-8")
        try:
            body = target.read_bytes()
        except Exception as e:
            return self._send(HTTPStatus.INTERNAL_SERVER_ERROR, str(e).encode(), "text/plain; charset=utf-8")
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if target.suffix.lower() in (".html", ".htm"):
            ctype = "text/html; charset=utf-8"
        return self._send(HTTPStatus.OK, body, ctype)

    def _send_soc_alert_events(self) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        last_digest = ""
        # Recycle the stream periodically so browser EventSource reconnect logic
        # can recover from stale LAN connections without user interaction.
        for _ in range(60):
            try:
                payload = cached_soc_alert_events_snapshot()
                raw = json.dumps(payload, separators=(",", ":"), sort_keys=True)
                stable_payload = dict(payload)
                stable_payload.pop("time", None)
                digest = _revision_digest(stable_payload)
                if digest != last_digest:
                    event_id = str(int(time.time()))
                    self.wfile.write(f"id: {event_id}\nevent: soc-alerts\ndata: {raw}\n\n".encode("utf-8"))
                    last_digest = digest
                else:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
                time.sleep(5)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return

    def reports_by_id(self) -> dict[str, Report]:
        return {r.rid: r for r in scan_reports()}

    def _admin_session_id(self) -> str:
        return parse_cookie_header(self.headers.get("Cookie")).get(ADMIN_SESSION_COOKIE, "")

    def _admin_authenticated(self) -> bool:
        session_id = self._admin_session_id()
        if not session_id:
            return False
        sessions = prune_admin_sessions()
        return admin_session_hash(session_id) in sessions

    def _require_admin_auth(self) -> bool:
        if self._admin_authenticated():
            return True
        self._redirect("/admin/login")
        return False

    def _soc_settings_write_authorized(self) -> bool:
        """Require an Administration session unless a dedicated service narrows the policy."""
        return self._admin_authenticated()

    def _cti_program_write_authorized(self) -> bool:
        """Keep CTI source and technology governance behind Administration."""
        return self._admin_authenticated()

    def _cti_program_mutation_audit(self, program: dict[str, object]) -> None:
        """Dedicated services may record a metadata-only CTI mutation event."""
        return None

    def _soc_review_write_authorized(self) -> bool:
        """Reject cross-site/form writes while keeping the LAN analyst UI usable."""
        content_type = str(self.headers.get("Content-Type") or "").lower()
        if not content_type.startswith("application/json"):
            return False
        if self.headers.get("X-Onion-Sentinel-Request") != "dashboard":
            return False
        fetch_site = str(self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if fetch_site and fetch_site != "same-origin":
            return False
        origin = str(self.headers.get("Origin") or "").strip()
        if origin:
            parsed_origin = urlparse(origin)
            request_host = str(self.headers.get("Host") or "").strip().lower()
            if (
                parsed_origin.scheme not in {"http", "https"}
                or not parsed_origin.netloc
                or parsed_origin.netloc.lower() != request_host
            ):
                return False
        return True

    def do_HEAD(self) -> None:
        parsed = urlparse(self.path)
        if is_head_route(
            parsed.path,
            cti_program_path=CTI_PROGRAM_API_PATH,
            prompt_paths=SOC_SETTINGS_PROMPT_API_PATHS,
        ):
            if parsed.path == "/admin" and not self._admin_authenticated():
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/admin/login")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", head_content_type(parsed.path))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
        else:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.end_headers()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        route = classify_post_route(
            parsed.path,
            cti_program_path=CTI_PROGRAM_API_PATH,
            prompt_paths=SOC_SETTINGS_PROMPT_API_PATHS,
        )
        is_cti_program_write = route.cti_program_write
        is_asset_write = route.asset_write
        is_incident_reanalysis = route.incident_reanalysis
        is_review_write = route.review_write
        if not route.accepted:
            return self._send(HTTPStatus.NOT_FOUND, b"Not found", "text/plain; charset=utf-8")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        request_limit = route.request_limit(cti_program.MAX_FILE_BYTES)
        if length <= 0 or length > request_limit:
            if route.json_request:
                return self._send(HTTPStatus.BAD_REQUEST, json.dumps({"ok": False, "error": "Invalid request size"}).encode(), "application/json; charset=utf-8")
            if parsed.path == "/admin/action" and self._admin_authenticated():
                return self._send(HTTPStatus.BAD_REQUEST, render_admin_dashboard("Invalid admin action request size.", True))
            return self._send(HTTPStatus.BAD_REQUEST, render_admin_login("Invalid request size.", True))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        if is_cti_program_write:
            if not self._soc_review_write_authorized():
                return self._send(
                    HTTPStatus.FORBIDDEN,
                    json.dumps({
                        "ok": False,
                        "error": "CTI workspace changes must come from the same-origin Onion Sentinel dashboard.",
                    }).encode(),
                    "application/json; charset=utf-8",
                )
            if not self._cti_program_write_authorized():
                return self._send(
                    HTTPStatus.FORBIDDEN,
                    json.dumps({
                        "ok": False,
                        "authentication_required": True,
                        "error": "Sign in to Onion Sentinel Administration before editing the CTI workspace.",
                    }).encode(),
                    "application/json; charset=utf-8",
                )
            payload = parse_json_body(raw).value_or(None)
            try:
                program = cti_program.save_program(payload)
            except cti_program.CTIProgramConflict as exc:
                return self._send(
                    HTTPStatus.CONFLICT,
                    json.dumps({"ok": False, "error": str(exc)}).encode(),
                    "application/json; charset=utf-8",
                )
            except cti_program.CTIProgramError as exc:
                return self._send(
                    HTTPStatus.BAD_REQUEST,
                    json.dumps({"ok": False, "error": str(exc)}).encode(),
                    "application/json; charset=utf-8",
                )
            except OSError:
                return self._send(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    json.dumps({"ok": False, "error": "Could not persist the CTI workspace."}).encode(),
                    "application/json; charset=utf-8",
                )
            self._cti_program_mutation_audit(program)
            return self._send(
                HTTPStatus.OK,
                json.dumps(cti_program.public_response(program), indent=2).encode(),
                "application/json; charset=utf-8",
            )
        if is_asset_write:
            if not self._soc_review_write_authorized():
                return self._send(
                    HTTPStatus.FORBIDDEN,
                    json.dumps({
                        "ok": False,
                        "error": (
                            "Asset inventory changes must come from the "
                            "same-origin Onion Sentinel dashboard."
                        ),
                    }).encode(),
                    "application/json; charset=utf-8",
                )
            if (
                ASSET_INVENTORY_ADMIN_WRITE_REQUIRED
                and not self._admin_authenticated()
            ):
                return self._send(
                    HTTPStatus.FORBIDDEN,
                    json.dumps({
                        "ok": False,
                        "authentication_required": True,
                        "error": (
                            "Sign in to Onion Sentinel Administration before "
                            "approving asset inventory changes."
                        ),
                    }).encode(),
                    "application/json; charset=utf-8",
                )
            payload = parse_json_body(raw).value_or(None)
            if parsed.path == "/api/assets/promote-dhcp":
                status, data = asset_dhcp_promotion_response(payload)
            elif parsed.path == "/api/assets/approve-dhcp-ip-change":
                status, data = asset_dhcp_ip_change_response(payload)
            elif parsed.path == "/api/assets/update":
                status, data = asset_update_response(payload)
            else:
                status, data = asset_demote_response(payload)
            return self._send(
                status,
                json.dumps(data, indent=2).encode(),
                "application/json; charset=utf-8",
            )
        if is_incident_reanalysis:
            if not self._soc_review_write_authorized():
                return self._send(
                    HTTPStatus.FORBIDDEN,
                    json.dumps({
                        "ok": False,
                        "error": "Incident reanalysis requests must come from the same-origin dashboard.",
                    }).encode(),
                    "application/json; charset=utf-8",
                )
            payload = parse_json_body(raw).value_or(None)
            if not isinstance(payload, dict):
                return self._send(
                    HTTPStatus.BAD_REQUEST,
                    json.dumps({
                        "ok": False,
                        "error": "Request body must be a JSON object.",
                    }).encode(),
                    "application/json; charset=utf-8",
                )
            status, data = dispatch_authorized_soc_write(
                route, payload, PORTAL_SOC_WRITE_CALLBACKS
            )
            if status < 400:
                SOC_ALERT_RESPONSE_CACHE.clear()
            return self._send(
                status,
                json.dumps(data, indent=2).encode(),
                "application/json; charset=utf-8",
            )
        if is_review_write:
            if not self._soc_review_write_authorized():
                return self._send(
                    HTTPStatus.FORBIDDEN,
                    json.dumps({
                        "ok": False,
                        "error": "Analyst review writes must come from the same-origin dashboard.",
                    }).encode(),
                    "application/json; charset=utf-8",
                )
            parsed_body = parse_json_body(raw)
            if not parsed_body.valid:
                return self._send(
                    HTTPStatus.BAD_REQUEST,
                    json.dumps({"ok": False, "error": "Request body must be valid JSON."}).encode(),
                    "application/json; charset=utf-8",
                )
            payload = parsed_body.value
            if not isinstance(payload, dict):
                return self._send(
                    HTTPStatus.BAD_REQUEST,
                    json.dumps({"ok": False, "error": "Request body must be a JSON object."}).encode(),
                    "application/json; charset=utf-8",
                )
            status, data = dispatch_authorized_soc_write(
                route, payload, PORTAL_SOC_WRITE_CALLBACKS
            )
            if status < 400:
                SOC_ALERT_RESPONSE_CACHE.clear()
            return self._send(
                status,
                json.dumps(data, indent=2).encode(),
                "application/json; charset=utf-8",
            )
        if route.alert_action:
            payload = parse_json_body(raw, empty_object=True).value_or({})
            status, data = dispatch_authorized_soc_write(
                route, payload, PORTAL_SOC_WRITE_CALLBACKS
            )
            if status < 400:
                SOC_ALERT_RESPONSE_CACHE.clear()
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path == "/api/soc-alerts/status":
            payload = parse_json_body(raw, empty_object=True).value_or({})
            ok, data = update_soc_alert_status(payload)
            if ok:
                SOC_ALERT_RESPONSE_CACHE.clear()
            response_status = (
                HTTPStatus.OK
                if ok
                else int(data.get("status") or HTTPStatus.BAD_REQUEST)
            )
            return self._send(response_status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path in SOC_SETTINGS_PROMPT_API_PATHS:
            payload = parse_json_body(raw, empty_object=True).value_or({})
            if not self._soc_settings_write_authorized():
                return self._send(HTTPStatus.FORBIDDEN, json.dumps({"ok": False, "error": "Sign in to Administration before saving SOC settings."}).encode(), "application/json; charset=utf-8")
            ok, data = save_settings_prompt(parsed.path, payload.get("prompt", ""))
            return self._send(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path == "/api/soc-settings/ai-model":
            payload = parse_json_body(raw, empty_object=True).value_or({})
            if not self._soc_settings_write_authorized():
                return self._send(HTTPStatus.FORBIDDEN, json.dumps({"ok": False, "error": "Sign in to Administration before saving SOC settings."}).encode(), "application/json; charset=utf-8")
            ok, data = save_soc_ai_settings(payload)
            return self._send(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path == "/api/soc-settings/agent-model":
            payload = parse_json_body(raw, empty_object=True).value_or({})
            if not self._soc_settings_write_authorized():
                return self._send(HTTPStatus.FORBIDDEN, json.dumps({"ok": False, "error": "Sign in to Administration before saving SOC settings."}).encode(), "application/json; charset=utf-8")
            ok, data = save_soc_agent_model(payload)
            return self._send(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path == "/api/admin/start-service":
            payload = parse_json_body(raw, empty_object=True).value_or({})
            if not self._admin_authenticated():
                return self._send(HTTPStatus.FORBIDDEN, json.dumps({"ok": False, "error": "Sign in before starting services."}).encode(), "application/json; charset=utf-8")
            if str(payload.get("token", "")) != ensure_admin_token():
                return self._send(HTTPStatus.FORBIDDEN, json.dumps({"ok": False, "error": "Admin action token validation failed."}).encode(), "application/json; charset=utf-8")
            service_id = str(payload.get("service", "")).strip()
            ok, message, status = start_admin_service(service_id)
            body = {"ok": ok, "message": message, "service": status}
            if not ok:
                body["error"] = message
            return self._send(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, json.dumps(body, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path.startswith("/api/resource-library/"):
            payload = parse_json_body(raw, empty_object=True).value_or({})
            if parsed.path == "/api/resource-library/remove":
                ok, data = move_resource_to_removal(str(payload.get("id", "")).strip(), str(payload.get("source", "")).strip())
            elif parsed.path == "/api/resource-library/tags":
                ok, data = set_resource_tags(str(payload.get("id", "")).strip(), payload.get("tags", []))
            elif parsed.path == "/api/resource-library/rename":
                ok, data = rename_resource_file(str(payload.get("id", "")).strip(), str(payload.get("source", "")).strip(), str(payload.get("new_name", "")).strip())
            elif parsed.path == "/api/resource-library/favorite":
                ok, data = set_resource_favorite(str(payload.get("id", "")).strip(), bool(payload.get("favorite")))
            else:
                ok, data = False, {"ok": False, "error": "Unknown Resource Library API"}
            return self._send(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        form = parse_qs(raw, keep_blank_values=True)
        token = form.get("token", [""])[0]
        if token != ensure_admin_token():
            if parsed.path == "/admin/action" and self._admin_authenticated():
                return self._send(HTTPStatus.FORBIDDEN, render_admin_dashboard("Admin action token validation failed.", True))
            return self._send(HTTPStatus.FORBIDDEN, render_admin_login("Form token validation failed.", True))
        if parsed.path == "/admin/login":
            if not admin_password_configured():
                return self._send(HTTPStatus.SERVICE_UNAVAILABLE, render_admin_login("Admin password is not configured yet. Run the local password setup script first.", True))
            password = form.get("password", [""])[0]
            if not verify_admin_password(password):
                return self._send(HTTPStatus.UNAUTHORIZED, render_admin_login("Invalid admin password.", True))
            session_id = create_admin_session(self.client_address[0])
            return self._redirect("/admin", {"Set-Cookie": admin_session_cookie_header(session_id)})
        if parsed.path == "/admin/logout":
            destroy_admin_session(self._admin_session_id())
            return self._redirect("/admin/login", {"Set-Cookie": expired_admin_session_cookie_header()})
        if not self._admin_authenticated():
            return self._send(HTTPStatus.FORBIDDEN, render_admin_login("Sign in before running Administration actions.", True))
        action_id = form.get("action", [""])[0]
        confirmation = form.get("confirmation", [""])[0]
        ok, message = start_admin_action(action_id, confirmation)
        query = f"?{'admin_msg' if ok else 'admin_error'}={quote(message)}"
        return self._redirect(f"/admin{query}", status=HTTPStatus.SEE_OTHER)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query, keep_blank_values=True)
        route = classify_get_route(path, cti_program_path=CTI_PROGRAM_API_PATH, prompt_paths=SOC_SETTINGS_PROMPT_API_PATHS)
        operation = route.operation
        if operation == "home":
            reports = scan_reports()
            body = render_home(reports, self.server.server_address[0], self.server.server_address[1])
            return self._send(HTTPStatus.OK, body)
        if operation == "admin_login":
            if self._admin_authenticated():
                return self._redirect("/admin")
            return self._send(HTTPStatus.OK, render_admin_login())
        if operation == "admin":
            if not self._require_admin_auth():
                return None
            admin_message = (query.get("admin_msg") or [""])[0]
            admin_error = (query.get("admin_error") or [""])[0]
            return self._send(HTTPStatus.OK, render_admin_dashboard(admin_message or admin_error, bool(admin_error)))
        if operation == "health":
            reports = scan_reports()
            roots = []
            for root in SCAN_ROOTS:
                info = {"path": str(root), "exists": root.exists(), "is_dir": root.is_dir(), "html_here": 0, "error": None}
                try:
                    info["html_here"] = len(list(root.glob("*.html"))) if root.exists() else 0
                except Exception as e:
                    info["error"] = repr(e)
                roots.append(info)
            data = {"ok": True, "reports": len(reports), "ip": local_ip(), "time": now_iso_local(), "roots": roots}
            return self._send(HTTPStatus.OK, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if operation == "admin_session_status":
            data = {
                "ok": True,
                "authenticated": self._admin_authenticated(),
                "required": ASSET_INVENTORY_ADMIN_WRITE_REQUIRED,
            }
            return self._send(
                HTTPStatus.OK,
                json.dumps(data, indent=2).encode(),
                "application/json; charset=utf-8",
            )
        if operation == "admin_service_status":
            if not self._admin_authenticated():
                return self._send(HTTPStatus.FORBIDDEN, json.dumps({"ok": False, "error": "Sign in before reading Administration service status."}).encode(), "application/json; charset=utf-8")
            return self._send(HTTPStatus.OK, json.dumps(defang_admin_service_json(admin_service_statuses()), indent=2).encode(), "application/json; charset=utf-8")
        if operation == "resource_favorites":
            data = {"ok": True, "favorites": resource_favorites()}
            return self._send(HTTPStatus.OK, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if operation == "system_health_beacons":
            data = n8n_beacon_history_response(query)
            return self._send(HTTPStatus.OK, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if operation == "asset_inventory":
            status, data = asset_inventory_response(query=query)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if operation == "dhcp_asset_discovery":
            status, data = dhcp_asset_discovery_response()
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if operation == "software_inventory":
            status, data = software_inventory_response(query=query)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if operation == "cti_program":
            try:
                data = cti_program.public_response(cti_program.load_program())
                status = HTTPStatus.OK
            except cti_program.CTIProgramError as exc:
                data = {"ok": False, "error": str(exc)}
                status = HTTPStatus.INTERNAL_SERVER_ERROR
            except OSError:
                data = {"ok": False, "error": "Could not read the CTI workspace."}
                status = HTTPStatus.INTERNAL_SERVER_ERROR
            return self._send(
                status,
                json.dumps(data, indent=2).encode(),
                "application/json; charset=utf-8",
            )
        if operation == "llm_analysis_current":
            return self._send(HTTPStatus.OK, json.dumps(read_llm_current_analysis(), indent=2).encode(), "application/json; charset=utf-8")
        if operation == "llm_analysis_logs":
            return self._send(HTTPStatus.OK, json.dumps(llm_analysis_logs_response(query), indent=2).encode(), "application/json; charset=utf-8")
        if operation == "soc_alert_events":
            return self._send_soc_alert_events()
        if operation == "soc_alert_status":
            return self._send(HTTPStatus.OK, json.dumps(soc_alert_status_response(), indent=2).encode(), "application/json; charset=utf-8")
        if operation == "soc_settings_prompt":
            data = read_settings_prompt(path)
            return self._send(HTTPStatus.OK if data.get("ok") else HTTPStatus.INTERNAL_SERVER_ERROR, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if operation == "soc_agent_memory":
            status, data = read_agent_memory((query.get("key") or [""])[0])
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if operation == "soc_ai_model":
            data = read_soc_ai_settings()
            return self._send(HTTPStatus.OK if data.get("ok") else HTTPStatus.INTERNAL_SERVER_ERROR, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if operation == "soc_ollama_models":
            force_refresh = (query.get("refresh") or [""])[0].strip().lower() in {"1", "true", "yes"}
            return self._send(HTTPStatus.OK, json.dumps(ollama_models_response(force_refresh), indent=2).encode(), "application/json; charset=utf-8")
        if operation == "soc_alerts":
            status, payload = cached_soc_alerts_query_response(query)
            return self._send(status, payload, "application/json; charset=utf-8")
        if operation == "soc_alert_metrics":
            status, data = soc_alert_metrics_response(query)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if operation == "soc_alert_suppressions":
            status, data = soc_alert_suppressions_response(query)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if operation == "soc_incidents":
            status, data = soc_incidents_query_response(query)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if operation == "soc_reanalysis_runs":
            status, data = soc_incident_reanalysis_runs_response(query)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if operation == "incident_adjudications":
            case_id = route.resource_id or ""
            case_status, group_id = _soc_incident_case_group_id(case_id)
            if case_status != HTTPStatus.OK:
                status, data = soc_alert_api_error(
                    "Incident case not found"
                    if case_status == HTTPStatus.NOT_FOUND
                    else "Invalid incident case id",
                    case_status,
                )
            else:
                try:
                    limit = int((query.get("limit") or ["25"])[0])
                except (TypeError, ValueError):
                    limit = 25
                status, data = soc_adjudication_history_response(
                    group_id,
                    case_id=case_id,
                    limit=limit,
                )
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if operation == "incident_detail":
            case_id = route.resource_id or ""
            status, data = soc_incident_detail_response(case_id)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if operation == "alert_adjudications":
            group_id = route.resource_id or ""
            try:
                limit = int((query.get("limit") or ["25"])[0])
            except (TypeError, ValueError):
                limit = 25
            status, data = soc_adjudication_history_response(group_id, limit=limit)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if operation == "alert_detail_fragment":
            group_id = route.resource_id or ""
            status, data = soc_alert_detail_fragment_response(group_id)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if operation == "alert_detail":
            alert_id = route.resource_id or ""
            status, data = soc_alert_detail_response(alert_id)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if operation == "resource_action_status":
            action_id = (query.get("id") or [""])[0]
            if not re.fullmatch(r"[a-f0-9-]{32,36}", action_id):
                return self._send(HTTPStatus.BAD_REQUEST, json.dumps({"ok": False, "error": "Invalid action id"}).encode(), "application/json; charset=utf-8")
            status_path = RESOURCE_LIBRARY_ACTION_STATUS_DIR / f"{action_id}.json"
            if not status_path.exists():
                return self._send(HTTPStatus.OK, json.dumps({"ok": True, "state": "pending"}).encode(), "application/json; charset=utf-8")
            return self._send(HTTPStatus.OK, status_path.read_bytes(), "application/json; charset=utf-8")
        catalog_route = classify_catalog_route(path)
        catalog_operation = catalog_route.operation
        if catalog_operation == "catalog_index":
            reports = scan_reports()
            data = [{"id": r.rid, "title": r.title, "path": r.rel, "category": r.category, "mtime": r.mtime, "size": r.size} for r in reports]
            return self._send(HTTPStatus.OK, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        metric_routes = {
            "metric_system_uptime": render_system_uptime_detail,
            "metric_updates": render_prioritized_updates_detail,
            "metric_macos_updates": render_macos_updates_detail,
            "metric_hermes_backups": render_hermes_backups_detail,
            "metric_local_disk": render_local_disk_detail,
        }
        if catalog_operation in metric_routes:
            return self._send(HTTPStatus.OK, metric_routes[catalog_operation]())
        if catalog_operation == "metric_portal_update":
            return self._send(HTTPStatus.OK, render_portal_update_detail(scan_reports()))
        # Backward-compatible static aliases for Forest Room 5. These make old
        # /open/<id> pages, cached pages, and direct LAN asset URLs resolve their
        # relative image/PDF links instead of showing alt-text-only blank cards.
        if catalog_operation == "forest_asset":
            base = (HOME / "report_portal" / "library" / "Prototype Web App" / "forest_room5_assets").resolve()
            target = (base / (catalog_route.asset_path or "")).resolve()
            try:
                target.relative_to(base)
            except ValueError:
                return self._send(HTTPStatus.FORBIDDEN, b"Forbidden", "text/plain; charset=utf-8")
            return self._serve_file(target)
        if catalog_operation == "qr_landing_source":
            return self._serve_file(HOME / "report_portal" / "library" / "Prototype Web App" / "qr_landing_source.pdf")
        if catalog_operation == "view_report":
            report = self.reports_by_id().get(catalog_route.report_id or "")
            if not report:
                return self._send(HTTPStatus.NOT_FOUND, b"Report not found", "text/plain; charset=utf-8")
            asset_rel = catalog_route.asset_path or ""
            if asset_rel in ("", "/"):
                target = report.path
            else:
                base = report.path.parent.resolve()
                target = (base / asset_rel).resolve()
                try:
                    target.relative_to(base)
                except ValueError:
                    return self._send(HTTPStatus.FORBIDDEN, b"Forbidden", "text/plain; charset=utf-8")
            if not target.is_file():
                return self._send(HTTPStatus.NOT_FOUND, b"Asset not found", "text/plain; charset=utf-8")
            try:
                body = target.read_bytes()
            except Exception as e:
                return self._send(HTTPStatus.INTERNAL_SERVER_ERROR, str(e).encode(), "text/plain; charset=utf-8")
            ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if target.suffix.lower() in (".html", ".htm"):
                ctype = "text/html; charset=utf-8"
            return self._send(HTTPStatus.OK, body, ctype)
        if catalog_operation in {"open_report", "download_report"}:
            report = self.reports_by_id().get(catalog_route.report_id or "")
            if not report:
                return self._send(HTTPStatus.NOT_FOUND, b"Report not found", "text/plain; charset=utf-8")
            if catalog_operation == "open_report":
                return self._redirect(f"/view/{report.rid}/")
            try:
                body = report.path.read_bytes()
            except Exception as e:
                return self._send(HTTPStatus.INTERNAL_SERVER_ERROR, str(e).encode(), "text/plain; charset=utf-8")
            ctype = mimetypes.guess_type(report.path.name)[0] or "text/html; charset=utf-8"
            extra = {"Content-Disposition": f"attachment; filename={quote(report.path.name)}"}
            return self._send(HTTPStatus.OK, body, ctype, extra)
        return self._send(HTTPStatus.NOT_FOUND, b"Not found", "text/plain; charset=utf-8")


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
