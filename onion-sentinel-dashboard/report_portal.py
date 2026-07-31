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
from artifact_cache import ArtifactCache
from http_runtime import BoundedResponseError, read_bounded_json
from jsonl_log import JsonlLogIndex
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
ASSET_STORE_ENV_FILE = HOME / "n8n-local" / ".env"
DHCP_ASSET_DISCOVERY_STATE_FILE = (
    HOME / "n8n-local" / "asset-discovery" / "dhcp-observations.json"
)
DHCP_ASSET_DISCOVERY_MAX_BYTES = 8 * 1024 * 1024
SOFTWARE_INVENTORY_STATE_FILE = (
    HOME / "n8n-local" / "software-inventory" / "software-inventory.json"
)
SOFTWARE_INVENTORY_MAX_BYTES = software_inventory.MAX_STATE_BYTES
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


@dataclass(frozen=True)
class SocAlertQuerySnapshot:
    statuses: dict
    status_counts: dict[str, int]
    active_total: int
    active_severity_counts: dict[str, int]
    active_highest_severity: str
    severity_counts: dict[str, int]
    highest_severity: str
    top_endpoints: dict[str, str]
    filtered_rows: list[sqlite3.Row]
    page_rows: list[sqlite3.Row | dict]
    total_matching: int
    total_pages: int
    current_page: int
    offset: int
    next_cursor: str | None


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
    status, payload = software_inventory.build_response(
        Path(SOFTWARE_INVENTORY_STATE_FILE),
        query,
        observed_at=observed_at,
        maximum_bytes=SOFTWARE_INVENTORY_MAX_BYTES,
    )
    if status != HTTPStatus.OK or not isinstance(payload.get("items"), list):
        return status, payload

    # Restricted-node responses keep endpoint hostnames pseudonymous. Resolve
    # those stable references only against the already-public authoritative
    # Asset Inventory. Ambiguous identifiers remain unlabeled.
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
    labeled = software_inventory.apply_asset_labels(
        payload["items"],
        assets,
        inventory_complete=asset_inventory_complete,
    )
    coverage = payload.get("coverage")
    if isinstance(coverage, dict):
        coverage["labeled_visible_records"] = labeled
        coverage["asset_label_inventory_complete"] = asset_inventory_complete
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
    if state_error:
        return HTTPStatus.SERVICE_UNAVAILABLE, {
            "ok": False,
            "error": f"DHCP discovery state unavailable: {state_error}",
            "collection": {"status": "invalid"},
            "counts": {
                "total": 0,
                "verified_match": 0,
                "candidate": 0,
                "conflict": 0,
                "stale": 0,
            },
            "observations": [],
        }

    inventory, inventory_error = load_asset_inventory_data()
    records = []
    counts = {
        "total": 0,
        "verified_match": 0,
        "candidate": 0,
        "conflict": 0,
        "stale": 0,
    }
    active_assets: dict[str, dict] = {}
    identity_indexes: dict[str, dict[str, set[str]]] = {
        "ip": {},
        "hostname": {},
        "mac": {},
    }
    if not inventory_error:
        for raw_asset in inventory.get("assets", []):
            if (
                not isinstance(raw_asset, dict)
                or _asset_record_state(raw_asset, now) != "current"
            ):
                continue
            public_asset = _asset_public_record(raw_asset, "current")
            asset_id = str(public_asset.get("asset_id") or "")
            if not asset_id:
                continue
            active_assets[asset_id] = public_asset
            identifiers = (
                raw_asset.get("identifiers")
                if isinstance(raw_asset.get("identifiers"), dict)
                else {}
            )
            for kind in identity_indexes:
                for raw_value in identifiers.get(kind) or []:
                    value = (
                        str(raw_value or "")
                        .strip()
                        .rstrip(".")
                        .lower()
                    )
                    if value:
                        identity_indexes[kind].setdefault(
                            value,
                            set(),
                        ).add(asset_id)

    def nonnegative_int(value: object, maximum: int = 2**63 - 1) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError, OverflowError):
            return 0
        return max(0, min(parsed, maximum))

    def text_list(value: object, maximum_items: int, maximum_length: int) -> list[str]:
        if not isinstance(value, list):
            return []
        return [
            str(item)[:maximum_length]
            for item in value[:maximum_items]
            if isinstance(item, (str, int, float))
        ]

    for raw in state.get("observations", []):
        if not isinstance(raw, dict):
            continue
        try:
            address = str(ipaddress.ip_address(str(raw.get("current_ip") or "").strip()))
            last_seen = parse_iso_timestamp(raw.get("last_seen"))
            if last_seen.tzinfo is None:
                raise ValueError("last_seen lacks offset")
            last_seen = last_seen.astimezone(dt.timezone.utc)
        except (TypeError, ValueError):
            continue
        observed_hostname = str(raw.get("hostname") or "").strip().rstrip(".").lower()
        observed_mac = str(raw.get("mac_address") or "").strip().lower()
        ip_matches = identity_indexes["ip"].get(address, set())
        hostname_matches = (
            identity_indexes["hostname"].get(observed_hostname, set())
            if observed_hostname
            else set()
        )
        mac_matches = (
            identity_indexes["mac"].get(observed_mac, set())
            if observed_mac
            else set()
        )
        stable_matches = hostname_matches | mac_matches
        all_matches = ip_matches | stable_matches
        resolution: dict = {
            "status": "unmapped",
            "ip": address,
        }
        if inventory_error:
            resolution["status"] = "inventory_unavailable"
        elif len(all_matches) > 1:
            resolution = {
                "status": "ambiguous",
                "ip": address,
                "asset_ids": sorted(all_matches),
            }
        elif len(all_matches) == 1:
            asset_id = next(iter(all_matches))
            asset = active_assets[asset_id]
            resolution = {
                "status": (
                    "resolved"
                    if asset.get("hostnames")
                    else "known_without_hostname"
                ),
                "ip": address,
                "asset_id": asset_id,
                "hostname": (
                    asset["hostnames"][0]
                    if asset.get("hostnames")
                    else ""
                ),
                "hostnames": list(asset.get("hostnames") or []),
                "role": str(asset.get("role") or ""),
                "platform": str(asset.get("platform") or ""),
                "criticality": str(
                    asset.get("criticality") or "unknown"
                ),
                "configured_ip_addresses": list(
                    asset.get("ip_addresses") or []
                ),
                "stable_identity_match": asset_id in stable_matches,
            }

        authoritative_hostnames = [
            str(value).strip().rstrip(".").lower()
            for value in resolution.get("hostnames", [])
            if str(value).strip()
        ]
        if resolution.get("status") in {"resolved", "known_without_hostname"}:
            if (
                observed_hostname
                and authoritative_hostnames
                and observed_hostname not in authoritative_hostnames
                and not resolution.get("stable_identity_match")
            ):
                reconciliation = "conflict"
                detail = "DHCP hostname differs from the authoritative assignment."
            elif address not in resolution.get(
                "configured_ip_addresses",
                [],
            ):
                reconciliation = "verified_match"
                detail = (
                    "A stable DHCP hostname or MAC maps this asset to a "
                    "new current address."
                )
            else:
                reconciliation = "verified_match"
                detail = "DHCP address agrees with the authoritative inventory."
        elif resolution.get("status") == "ambiguous":
            reconciliation = "conflict"
            detail = "More than one authoritative asset claims this address."
        else:
            reconciliation = "candidate"
            detail = "Review before adding this observation to the authoritative inventory."
        lease_expires = None
        if raw.get("lease_expires_at"):
            try:
                lease_expires = parse_iso_timestamp(raw["lease_expires_at"]).astimezone(dt.timezone.utc)
            except (TypeError, ValueError):
                lease_expires = None
        stale = last_seen < now - dt.timedelta(hours=24) and (
            lease_expires is None or lease_expires < now
        )
        counts[reconciliation] += 1
        if stale:
            counts["stale"] += 1
        counts["total"] += 1
        records.append({
            "discovery_id": str(raw.get("discovery_id") or "")[:64],
            "reconciliation": reconciliation,
            "reconciliation_detail": detail,
            "stale": stale,
            "current_ip": address,
            "ip_addresses": text_list(raw.get("ip_addresses"), 32, 64),
            "mac_address": str(raw.get("mac_address") or "")[:32],
            "mac_address_scope": _mac_address_scope(raw.get("mac_address")),
            "hostname": str(raw.get("hostname") or "")[:253],
            "hostnames": text_list(raw.get("hostnames"), 32, 253),
            "first_seen": str(raw.get("first_seen") or "")[:64],
            "last_seen": str(raw.get("last_seen") or "")[:64],
            "lease_expires_at": str(raw.get("lease_expires_at") or "")[:64],
            "message_types": text_list(raw.get("message_types"), 16, 80),
            "sensors": text_list(raw.get("sensors"), 16, 160),
            "observation_count": nonnegative_int(raw.get("observation_count")),
            "authoritative_asset": {
                "asset_id": str(resolution.get("asset_id") or ""),
                "hostname": str(resolution.get("hostname") or ""),
                "hostnames": authoritative_hostnames,
                "role": str(resolution.get("role") or ""),
                "platform": str(resolution.get("platform") or ""),
                "criticality": str(resolution.get("criticality") or ""),
                "configured_ip_addresses": list(
                    resolution.get("configured_ip_addresses") or []
                )[:32],
            } if resolution.get("status") in {"resolved", "known_without_hostname"} else None,
        })
    rank = {"conflict": 0, "candidate": 1, "verified_match": 2}
    records.sort(
        key=lambda item: (
            rank.get(str(item["reconciliation"]), 9),
            bool(item["stale"]),
            str(item["last_seen"]),
        )
    )
    collection = state.get("collection") or {}
    public_collection = {
        "status": str(collection.get("status") or "unknown")[:32],
        "last_attempt_at": str(collection.get("last_attempt_at") or "")[:64],
        "last_success_at": str(collection.get("last_success_at") or "")[:64],
        "last_error": str(collection.get("last_error") or "")[:300],
        "last_window": collection.get("last_window") if isinstance(collection.get("last_window"), dict) else {},
        "last_returned": nonnegative_int(collection.get("last_returned"), 1000),
        "last_hits_total": nonnegative_int(collection.get("last_hits_total")),
        "last_truncated": bool(collection.get("last_truncated")),
        "last_query_segments": nonnegative_int(
            collection.get("last_query_segments"),
            64,
        ),
    }
    backfill = state.get("backfill") if isinstance(state.get("backfill"), dict) else {}
    public_backfill = {
        "status": str(backfill.get("status") or "never_run")[:32],
        "last_attempt_at": str(backfill.get("last_attempt_at") or "")[:64],
        "last_success_at": str(backfill.get("last_success_at") or "")[:64],
        "last_error": str(backfill.get("last_error") or "")[:300],
        "requested_start": str(backfill.get("requested_start") or "")[:64],
        "requested_end": str(backfill.get("requested_end") or "")[:64],
        "covered_through": str(backfill.get("covered_through") or "")[:64],
        "last_returned": nonnegative_int(backfill.get("last_returned"), 1_000_000),
        "last_hits_total": nonnegative_int(backfill.get("last_hits_total")),
        "last_query_segments": nonnegative_int(
            backfill.get("last_query_segments"),
            64,
        ),
    }
    return HTTPStatus.OK, {
        "ok": True,
        "updated_at": str(state.get("updated_at") or ""),
        "observed_at": format_iso_timestamp(now, utc_z=True),
        "authoritative_inventory_status": (
            "unavailable" if inventory_error else str(inventory.get("inventory_status") or "loaded")
        ),
        "collection": public_collection,
        "backfill": public_backfill,
        "counts": counts,
        "observations": records,
    }


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


def _pcap_relay_workflow_state(now_utc: dt.datetime) -> dict[str, object]:
    """Read the latest authenticated relay broker state from alert-store.

    The state is considered actionable for only three minutes. A stale safety
    hold must never grant an indefinite health exemption if the relay, n8n, or
    state writer stops reporting.
    """
    state_path = _freshest_existing_path([
        SOC_ALERT_PCAP_WORKFLOW_STATE_FILE,
        HOME / "SOC Alerts Web" / "pcap-workflow-state.json",
        HOME / "n8n-local" / "alert_store_data" / "pcap-workflow-state.json",
    ])
    raw = _safe_read_json(state_path, {}) if state_path else {}
    workflow = raw.get("pcap_workflow") if isinstance(raw, dict) else {}
    workflow = workflow if isinstance(workflow, dict) else {}
    generated_at = raw.get("generated_at") if isinstance(raw, dict) else None
    report_age_seconds: int | None = None
    if generated_at:
        try:
            reported_at = parse_iso_timestamp(generated_at).astimezone(dt.timezone.utc)
            report_age_seconds = max(0, int((now_utc - reported_at).total_seconds()))
        except Exception:
            generated_at = None
    state = str(workflow.get("state") or "unknown")
    fresh = report_age_seconds is not None and report_age_seconds <= 3 * 60
    def nonnegative_int(value: object) -> int:
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError, OverflowError):
            return 0

    return {
        "available": bool(state_path and workflow),
        "state": state,
        "active": bool(fresh and state == "capture_protection_hold" and workflow.get("deferred")),
        "fresh": fresh,
        "reported_at": generated_at,
        "report_age_seconds": report_age_seconds,
        "relay_host": raw.get("relay_host") if isinstance(raw, dict) else None,
        "reason": str(workflow.get("reason") or "")[:300],
        "metric": str(workflow.get("metric") or "")[:64],
        "observed_percent": workflow.get("observed_percent"),
        "threshold_percent": workflow.get("threshold_percent"),
        "telemetry_age_seconds": workflow.get("telemetry_age_seconds"),
        "processed": nonnegative_int(workflow.get("processed")),
        "operational_failures": nonnegative_int(workflow.get("operational_failures")),
    }


def pcap_workflow_health_response() -> dict[str, object]:
    """Return compact PCAP broker/parser health for the System Health page."""
    summary: dict[str, object] = {
        "available": False,
        "request_counts": {"pending": 0, "claimed": 0, "fulfilled": 0, "failed": 0, "total": 0},
        "no_packet_failures": 0,
        "oversize_failures": 0,
        "outcome_counts": {},
        "storage": {},
        "warning_count": 0,
        "warnings": [],
        "advisories": [],
        "active_transfers": [],
        "queue_progressing": False,
        "last_progress_at": None,
        "last_progress_age_seconds": None,
        "recent_requests": [],
        "latest_request": None,
        "analysis_count": 0,
        "latest_analysis": None,
        "artifact_size_bytes": directory_size_bytes(SOC_ALERT_PCAP_ARTIFACT_DIR),
    }
    now_utc = dt.datetime.now(dt.timezone.utc)
    relay_workflow = _pcap_relay_workflow_state(now_utc)
    summary["capture_protection"] = relay_workflow
    if relay_workflow.get("active"):
        reason = str(relay_workflow.get("reason") or "Security Onion capture telemetry is above its safety threshold")
        summary["advisories"] = [f"PCAP reads are safely paused: {reason}"]
    try:
        if SOC_ALERT_STORE_DB.exists():
            with soc_alert_db_connect() as conn:
                if sqlite_table_exists(conn, "pcap_requests"):
                    pcap_columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(pcap_requests)")}
                    has_outcome = "outcome" in pcap_columns
                    has_transfer_duration = "transfer_duration_seconds" in pcap_columns
                    counts = {
                        str(row["status"] or "unknown").lower(): int(row["count"] or 0)
                        for row in conn.execute("SELECT status, COUNT(*) AS count FROM pcap_requests GROUP BY status")
                    }
                    total = sum(counts.values())
                    summary["request_counts"] = {
                        "pending": counts.get("pending", 0),
                        "claimed": counts.get("claimed", 0),
                        "fulfilled": counts.get("fulfilled", 0),
                        "failed": counts.get("failed", 0),
                        "total": total,
                    }
                    if has_outcome:
                        summary["outcome_counts"] = {
                            str(row["outcome"] or "unknown"): int(row["count"] or 0)
                            for row in conn.execute("SELECT COALESCE(outcome, 'unknown') AS outcome, COUNT(*) AS count FROM pcap_requests GROUP BY COALESCE(outcome, 'unknown')")
                        }
                    storage = conn.execute(
                        """
                        SELECT COUNT(*) AS fulfilled_count,
                               COALESCE(SUM(artifact_size_bytes), 0) AS bytes_total,
                               COALESCE(AVG(artifact_size_bytes), 0) AS bytes_average,
                               COALESCE(MAX(artifact_size_bytes), 0) AS bytes_maximum,
                               COALESCE(SUM(CASE WHEN datetime(replace(completed_at, '  ', 'T')) >= datetime('now', '-24 hours') THEN artifact_size_bytes ELSE 0 END), 0) AS bytes_24h
                        FROM pcap_requests WHERE status = 'fulfilled'
                        """
                    ).fetchone()
                    summary["storage"] = {key: int(storage[key] or 0) for key in storage.keys()} if storage else {}
                    no_packets_sql = "SELECT COUNT(*) AS count FROM pcap_requests WHERE outcome = 'no_packets_available'" if has_outcome else "SELECT COUNT(*) AS count FROM pcap_requests WHERE status = 'failed' AND lower(coalesce(error, '')) LIKE '%no matching packets%'"
                    no_packets = conn.execute(no_packets_sql).fetchone()
                    summary["no_packet_failures"] = int(no_packets["count"] or 0) if no_packets else 0
                    oversize_sql = "SELECT COUNT(*) AS count FROM pcap_requests WHERE outcome = 'oversize'" if has_outcome else "SELECT COUNT(*) AS count FROM pcap_requests WHERE status = 'failed' AND lower(coalesce(error, '')) LIKE '%artifact exceeds inline transfer limit%'"
                    oversize = conn.execute(oversize_sql).fetchone()
                    summary["oversize_failures"] = int(oversize["count"] or 0) if oversize else 0
                    unexpected_where = "outcome NOT IN ('no_packets_available', 'expired', 'oversize')" if has_outcome else "lower(coalesce(error, '')) NOT LIKE '%no matching packets%' AND lower(coalesce(error, '')) NOT LIKE '%artifact exceeds inline transfer limit%' AND lower(coalesce(error, '')) NOT LIKE '%invalid json:%preview=''''%'"
                    unexpected_failure_rows = conn.execute(
                        f"""
                        SELECT error, completed_at, updated_at, created_at
                        FROM pcap_requests
                        WHERE status = 'failed'
                          AND {unexpected_where}
                        """
                    ).fetchall()
                    failure_cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)
                    unexpected_failure_count = 0
                    for row in unexpected_failure_rows:
                        try:
                            failure_at = parse_iso_timestamp(row["completed_at"] or row["updated_at"] or row["created_at"])
                        except Exception:
                            unexpected_failure_count += 1
                            continue
                        if failure_at.astimezone(dt.timezone.utc) >= failure_cutoff:
                            unexpected_failure_count += 1
                    stale_cutoff = now_utc - dt.timedelta(minutes=20)
                    has_transfer_progress = {
                        "transfer_stage", "transfer_bytes", "transfer_total_bytes", "transfer_progress_at"
                    }.issubset(pcap_columns)
                    active_transfers: list[dict[str, object]] = []
                    if has_transfer_progress:
                        progress_rows = conn.execute(
                            """
                            SELECT request_id, transfer_stage, transfer_bytes,
                                   transfer_total_bytes, transfer_progress_at
                            FROM pcap_requests
                            WHERE status = 'claimed' AND transfer_progress_at IS NOT NULL
                            """
                        ).fetchall()
                        progress_cutoff = now_utc - dt.timedelta(minutes=2)
                        for progress_row in progress_rows:
                            try:
                                progress_at = parse_iso_timestamp(progress_row["transfer_progress_at"])
                            except Exception:
                                continue
                            if progress_at.astimezone(dt.timezone.utc) < progress_cutoff:
                                continue
                            total_bytes = int(progress_row["transfer_total_bytes"] or 0)
                            transferred_bytes = int(progress_row["transfer_bytes"] or 0)
                            active_transfers.append({
                                "request_id": progress_row["request_id"] or "",
                                "stage": progress_row["transfer_stage"] or "",
                                "transferred_bytes": transferred_bytes,
                                "total_bytes": total_bytes,
                                "progress_at": progress_row["transfer_progress_at"] or "",
                            })
                    summary["active_transfers"] = active_transfers
                    latest_terminal = conn.execute(
                        """
                        SELECT COALESCE(completed_at, updated_at) AS progress_at
                        FROM pcap_requests
                        WHERE status IN ('fulfilled', 'failed')
                          AND COALESCE(completed_at, updated_at) IS NOT NULL
                        ORDER BY COALESCE(completed_at, updated_at) DESC
                        LIMIT 1
                        """
                    ).fetchone()
                    last_progress_at = latest_terminal["progress_at"] if latest_terminal else None
                    last_progress_age_seconds: int | None = None
                    if last_progress_at:
                        try:
                            parsed_progress_at = parse_iso_timestamp(last_progress_at).astimezone(dt.timezone.utc)
                            last_progress_age_seconds = max(0, int((now_utc - parsed_progress_at).total_seconds()))
                        except Exception:
                            last_progress_at = None
                    # A completion-based timer has a short, intentional idle
                    # interval between serial jobs. Preserve that interval as
                    # forward progress, but bound it tightly so a dead broker
                    # becomes unhealthy instead of receiving indefinite grace.
                    recent_terminal_progress = (
                        int(summary["request_counts"]["pending"] or 0) > 0
                        and last_progress_age_seconds is not None
                        and last_progress_age_seconds <= 3 * 60
                    )
                    queue_progressing = bool(active_transfers) or recent_terminal_progress
                    summary["queue_progressing"] = queue_progressing
                    summary["last_progress_at"] = last_progress_at
                    summary["last_progress_age_seconds"] = last_progress_age_seconds
                    # A serial broker can legitimately leave queued work older
                    # than 20 minutes behind a multi-gigabyte transfer. Use a
                    # deliberately pessimistic 4 MiB/s floor, 1.5x headroom,
                    # and a bounded queue multiplier. Fresh heartbeats are
                    # required; a silent transfer immediately loses this grace.
                    pending_grace = dt.timedelta(minutes=20)
                    if active_transfers:
                        largest_active = max(int(item["total_bytes"] or 0) for item in active_transfers)
                        transfer_seconds = min(
                            6 * 60 * 60,
                            max(20 * 60, int(largest_active / (4 * 1024 * 1024) * 1.5) + 10 * 60),
                        )
                        pending_total = int(summary["request_counts"]["pending"] or 0)
                        pending_grace = dt.timedelta(
                            seconds=min(12 * 60 * 60, 20 * 60 + transfer_seconds * max(1, pending_total))
                        )
                    stale_rows = conn.execute(
                        f"""
                        SELECT status, updated_at, created_at
                               {', transfer_progress_at' if has_transfer_progress else ''}
                        FROM pcap_requests WHERE status IN ('pending', 'claimed')
                        """
                    ).fetchall()
                    stale_counts: dict[str, int] = {}
                    for row in stale_rows:
                        try:
                            freshness_value = (
                                row["transfer_progress_at"]
                                if has_transfer_progress and row["status"] == "claimed" and row["transfer_progress_at"]
                                else row["updated_at"] or row["created_at"]
                            )
                            updated_at = parse_iso_timestamp(freshness_value)
                        except Exception:
                            continue
                        if row["status"] == "pending" and (queue_progressing or relay_workflow.get("active")):
                            continue
                        row_cutoff = now_utc - pending_grace if row["status"] == "pending" else stale_cutoff
                        if updated_at.astimezone(dt.timezone.utc) < row_cutoff:
                            status = str(row["status"] or "unknown")
                            stale_counts[status] = stale_counts.get(status, 0) + 1
                    warnings: list[str] = []
                    for status, count in sorted(stale_counts.items()):
                        warnings.append(f"{count} {status} PCAP request(s) older than 20 minutes")
                    if unexpected_failure_count:
                        warnings.append(f"{unexpected_failure_count} PCAP request failure(s) need review")
                    if (
                        relay_workflow.get("available")
                        and not relay_workflow.get("fresh")
                        and int(summary["request_counts"]["pending"] or 0) > 0
                        and not queue_progressing
                    ):
                        # A multi-gigabyte transfer can outlive the broker's
                        # between-run status event. Fresh byte progress from the
                        # claimed request is the stronger liveness signal; warn
                        # only when both telemetry sources have gone quiet.
                        warnings.append("PCAP broker safety telemetry is stale")
                    if (
                        relay_workflow.get("fresh")
                        and relay_workflow.get("state") == "operational_failure"
                    ):
                        warnings.append("PCAP broker reports an operational failure")
                    summary["warnings"] = warnings
                    summary["warning_count"] = len(warnings)
                    latest = conn.execute(
                        f"""
                        SELECT request_id, status, error, group_id, claimed_at, updated_at, completed_at
                               {', outcome' if has_outcome else ''}
                               {', transfer_duration_seconds' if has_transfer_duration else ''}
                        FROM pcap_requests
                        ORDER BY COALESCE(completed_at, updated_at, created_at) DESC
                        LIMIT 1
                        """
                    ).fetchone()
                    if latest:
                        summary["latest_request"] = {
                            "request_id": latest["request_id"],
                            "status": latest["status"],
                            "outcome": latest["outcome"] if has_outcome else "",
                            "error": latest["error"] or "",
                            "group_id": latest["group_id"] or "",
                            "updated_at": latest["completed_at"] or latest["updated_at"] or "",
                            "transfer_duration_seconds": pcap_transfer_duration_seconds(
                                latest, has_transfer_duration=has_transfer_duration
                            ),
                        }
                    recent = conn.execute(
                        f"""
                        SELECT request_id, status, error, group_id, artifact_size_bytes, claimed_at,
                               updated_at, completed_at, created_at
                               {', outcome' if has_outcome else ''}
                               {', transfer_duration_seconds' if has_transfer_duration else ''}
                        FROM pcap_requests
                        ORDER BY COALESCE(completed_at, updated_at, created_at) DESC
                        LIMIT 250
                        """
                    ).fetchall()
                    summary["recent_requests"] = [
                        {
                            "request_id": row["request_id"] or "",
                            "status": row["status"] or "",
                            "outcome": row["outcome"] if has_outcome else "",
                            "error": row["error"] or "",
                            "group_id": row["group_id"] or "",
                            "artifact_size_bytes": int(row["artifact_size_bytes"] or 0),
                            "transfer_duration_seconds": pcap_transfer_duration_seconds(
                                row, has_transfer_duration=has_transfer_duration
                            ),
                            "updated_at": row["completed_at"] or row["updated_at"] or row["created_at"] or "",
                        }
                        for row in recent
                    ]
                    summary["available"] = True
    except Exception as exc:
        summary["error"] = str(exc)[:240]

    latest_analysis: Path | None = None
    if SOC_ALERT_PCAP_ANALYSIS_DIR.exists():
        analysis_files = [path for path in SOC_ALERT_PCAP_ANALYSIS_DIR.glob("*-pcap-analysis.json") if path.is_file()]
        summary["analysis_count"] = len(analysis_files)
        if analysis_files:
            latest_analysis = max(analysis_files, key=lambda path: path.stat().st_mtime)
    if latest_analysis:
        summary["latest_analysis"] = {
            "name": latest_analysis.name,
            "updated_at": format_iso_timestamp(dt.datetime.fromtimestamp(latest_analysis.stat().st_mtime, dt.timezone.utc).astimezone(), timespec="seconds"),
            "size_bytes": latest_analysis.stat().st_size,
        }
    return summary


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


MAXMIND_GEOIP_DATABASE_SETTINGS = {
    "asn": (
        "maxmind_geoip_asn_db_path",
        "~/n8n-local/config/maxmind/GeoLite2-ASN.mmdb",
    ),
    "city": (
        "maxmind_geoip_city_db_path",
        "~/n8n-local/config/maxmind/GeoLite2-City.mmdb",
    ),
    "country": (
        "maxmind_geoip_country_db_path",
        "~/n8n-local/config/maxmind/GeoLite2-Country.mmdb",
    ),
}

CYBER_SECURITY_AGENT_ROLES = (
    "soc-analyst",
    "incident-responder",
    "siem-engineer",
    "cyber-threat-intel",
    "threat-hunter",
)
SOC_AI_SETTINGS_LOCK = threading.RLock()
CODEX_CLI_REASONING_EFFORTS = frozenset({"low", "medium", "high", "xhigh"})
HERMES_AGENT_REASONING_EFFORT = "medium"
CODEX_CLI_MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
CLI_HARNESS_MODEL_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,239}$"
)
OPENCLAW_SUPPORTED_OLLAMA_URLS = frozenset({
    "http://127.0.0.1:11434",
    "http://localhost:11434",
})
CODEX_CLI_MODEL_CATALOG = (
    "gpt-5.5",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
    "gpt-5.6-luna",
)
SOC_ANALYSIS_SEVERITY_THRESHOLDS = frozenset(
    {"disabled", "critical", "high", "medium", "low", "informational"}
)
SOC_ANALYSIS_SEVERITY_ORDER = (
    "informational",
    "low",
    "medium",
    "high",
    "critical",
)


def default_soc_ai_settings() -> dict:
    """Return safe AI analysis routing defaults for the Settings page and runner."""
    default_model = os.environ.get("SOC_AI_MODEL") or "devstral:latest"
    return {
        "mode": "ollama",
        "ollama_model": default_model,
        "enabled_ollama_models": [default_model],
        "ollama_url": os.environ.get("OLLAMA_URL") or "http://127.0.0.1:11434",
        "cloud_provider": "codex-cli",
        "cloud_model": "gpt-5.5",
        "cloud_command": "",
        "codex_cli_path": "codex",
        "codex_cli_model": "gpt-5.5",
        "codex_cli_reasoning_effort": "medium",
        "codex_cli_models": [
            {"model": model, "reasoning_effort": "medium", "enabled": False}
            for model in CODEX_CLI_MODEL_CATALOG
        ],
        "gpt_cli_enabled": False,
        "hermes_agent_enabled": False,
        "hermes_agent_path": "hermes",
        "hermes_agent_model": "gpt-5.5",
        "hermes_agent_reasoning_effort": "medium",
        "openclaw_enabled": False,
        "openclaw_path": "openclaw",
        "openclaw_model": "ollama/gemma4:26b-mlx",
        "openclaw_reasoning_effort": "medium",
        # Automatic base analysis is independently configurable from evidence
        # collection and case creation.
        "soc_analyst_analysis_min_severity": "informational",
        # Preserve the deployed all-alert PCAP policy unless an operator
        # deliberately raises the floor in Settings.
        "soc_analyst_pcap_min_severity": "informational",
        # Automatic case creation is opt-in because it changes analyst state.
        "soc_analyst_incident_min_severity": "disabled",
        "agent_models": {
            role: f"ollama:{default_model}"
            for role in CYBER_SECURITY_AGENT_ROLES
        },
        "agent_second_opinion_models": {
            role: ""
            for role in CYBER_SECURITY_AGENT_ROLES
        },
        **{
            setting_key: default_path
            for setting_key, default_path in MAXMIND_GEOIP_DATABASE_SETTINGS.values()
        },
}


def _normalized_model_list(value: object) -> list[str]:
    """Return a bounded, ordered model roster without duplicate or control-text entries."""
    if not isinstance(value, list):
        return []
    models: list[str] = []
    for item in value[:32]:
        model = str(item or "").strip()[:240]
        if not model or re.search(r"[\x00-\x1f\x7f]", model) or model in models:
            continue
        models.append(model)
    return models


def _boolean_setting(value: object, default: bool = False) -> bool:
    """Normalize booleans without treating the string ``false`` as truthy."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on", "enabled"}:
            return True
        if normalized in {"0", "false", "no", "off", "disabled", ""}:
            return False
    return default


def _derive_model_mode(enabled_ollama_models: list[str], gpt_cli_enabled: bool) -> str:
    """Keep the legacy mode field deterministic for rolling-deploy compatibility."""
    if enabled_ollama_models and gpt_cli_enabled:
        return "hybrid"
    if gpt_cli_enabled:
        return "cloud"
    return "ollama"


def _codex_cli_route(model: str, effort: str) -> str:
    return f"codex-cli:{model}:{effort}"


def _hermes_agent_route(model: str, effort: str) -> str:
    return f"hermes-agent:{model}:{effort}"


def _openclaw_route(model: str, effort: str) -> str:
    return f"openclaw:{model}:{effort}"


def _valid_cli_executable_path(value: str, basename: str) -> bool:
    """Accept only an exact command name or an absolute path to that command."""
    if (
        not value
        or len(value) > 1024
        or re.search(r"[\x00-\x1f\x7f]", value)
    ):
        return False
    path = Path(value)
    if not path.is_absolute():
        return value == basename
    return bool(
        path.name == basename
        and re.fullmatch(r"/[A-Za-z0-9._/+-]+", value)
    )


def _valid_provider_model(value: str) -> bool:
    """Validate an argv-safe provider model identifier, including namespaced models."""
    return bool(
        value
        and len(value) <= 240
        and not re.search(r"[\x00-\x1f\x7f]", value)
    )


def _valid_openclaw_model(value: str) -> bool:
    """Limit the isolated OpenClaw adapter to credential-free Ollama routes."""
    return bool(
        CLI_HARNESS_MODEL_PATTERN.fullmatch(value)
        and value.lower().startswith("ollama/")
        and len(value) > len("ollama/")
    )


def _normalize_codex_cli_models(
    value: object,
    *,
    legacy_model: str,
    legacy_effort: str,
    legacy_enabled: bool,
) -> tuple[bool, list[dict]]:
    """Validate settings for the fixed, one-row-per-model Codex catalog."""
    raw_entries = value if isinstance(value, list) else [
        {
            "model": legacy_model,
            "reasoning_effort": legacy_effort,
            "enabled": legacy_enabled,
        }
    ]
    if len(raw_entries) > len(CODEX_CLI_MODEL_CATALOG):
        return False, []
    configured: dict[str, dict] = {}
    for raw in raw_entries:
        if not isinstance(raw, dict):
            return False, []
        model = str(raw.get("model") or "").strip()
        effort = str(raw.get("reasoning_effort") or "medium").strip().lower()
        if model not in CODEX_CLI_MODEL_CATALOG:
            return False, []
        if effort not in CODEX_CLI_REASONING_EFFORTS:
            return False, []
        if model in configured:
            return False, []
        configured[model] = {
            "model": model,
            "reasoning_effort": effort,
            "enabled": _boolean_setting(raw.get("enabled")),
        }
    return True, [
        configured.get(model, {
            "model": model,
            "reasoning_effort": "medium",
            "enabled": False,
        })
        for model in CODEX_CLI_MODEL_CATALOG
    ]


def _enabled_agent_model_routes(
    enabled_ollama_models: list[str],
    codex_cli_models: list[dict],
    *,
    hermes_agent_enabled: bool = False,
    hermes_agent_model: str = "gpt-5.5",
    hermes_agent_reasoning_effort: str = "medium",
    openclaw_enabled: bool = False,
    openclaw_model: str = "ollama/gemma4:26b-mlx",
    openclaw_reasoning_effort: str = "medium",
) -> list[str]:
    """Return stable route identifiers that agents may be assigned to."""
    routes = [f"ollama:{model}" for model in enabled_ollama_models]
    routes.extend(
        _codex_cli_route(entry["model"], entry["reasoning_effort"])
        for entry in codex_cli_models
        if entry.get("enabled") is True
    )
    if hermes_agent_enabled:
        routes.append(
            _hermes_agent_route(
                hermes_agent_model,
                hermes_agent_reasoning_effort,
            )
        )
    if openclaw_enabled:
        routes.append(
            _openclaw_route(
                openclaw_model,
                openclaw_reasoning_effort,
            )
        )
    return routes


def _canonical_agent_route(route: object, enabled_routes: list[str]) -> str:
    """Migrate the legacy provider-only route to the first enabled Codex entry."""
    normalized = str(route or "").strip()[:260]
    if normalized in {"gpt-cli", "codex-cli"}:
        return next(
            (candidate for candidate in enabled_routes if candidate.startswith("codex-cli:")),
            normalized,
        )
    if normalized.startswith("codex-cli:") and normalized not in enabled_routes:
        try:
            model, _ = normalized.removeprefix("codex-cli:").rsplit(":", 1)
        except ValueError:
            return normalized
        return next(
            (
                candidate
                for candidate in enabled_routes
                if candidate.startswith(f"codex-cli:{model}:")
            ),
            normalized,
        )
    for provider in ("hermes-agent", "openclaw"):
        prefix = f"{provider}:"
        if normalized.startswith(prefix) and normalized not in enabled_routes:
            return next(
                (
                    candidate
                    for candidate in enabled_routes
                    if candidate.startswith(prefix)
                ),
                normalized,
            )
    return normalized


def _model_route_identity(
    route: object,
    settings: dict | None = None,
) -> str:
    """Return the effort-independent provider/model identity used by runtime."""
    normalized = str(route or "").strip().lower()
    if normalized.startswith("codex-cli:"):
        try:
            model, effort = normalized.removeprefix("codex-cli:").rsplit(":", 1)
        except ValueError:
            return normalized
        if model and effort in CODEX_CLI_REASONING_EFFORTS:
            return f"openai-codex:{model}"
    if normalized in {"gpt-cli", "codex-cli"}:
        configured = str(
            (settings or {}).get("codex_cli_model") or "configured-default"
        ).strip().lower()
        return f"openai-codex:{configured}"
    if normalized.startswith("hermes-agent:"):
        try:
            model, effort = normalized.removeprefix("hermes-agent:").rsplit(":", 1)
        except ValueError:
            return normalized
        if model and effort in CODEX_CLI_REASONING_EFFORTS:
            return f"openai-codex:{model}"
    if normalized.startswith("openclaw:"):
        try:
            model, effort = normalized.removeprefix("openclaw:").rsplit(":", 1)
        except ValueError:
            return normalized
        if model and effort in CODEX_CLI_REASONING_EFFORTS:
            if "/" in model:
                provider, name = model.split("/", 1)
                return f"{provider}:{name}"
            return f"openclaw:{model}"
    return normalized


def _normalize_agent_models(value: object, enabled_routes: list[str]) -> dict[str, str]:
    """Keep every agent on exactly one enabled route after roster changes."""
    raw = value if isinstance(value, dict) else {}
    fallback = enabled_routes[0]
    assignments: dict[str, str] = {}
    for role in CYBER_SECURITY_AGENT_ROLES:
        route = _canonical_agent_route(raw.get(role), enabled_routes)
        assignments[role] = route if route in enabled_routes else fallback
    return assignments


def _normalize_agent_second_opinion_models(
    value: object,
    enabled_routes: list[str],
    primary_assignments: dict[str, str],
    settings: dict | None = None,
) -> dict[str, str]:
    """Validate optional secondary routes without inventing a fallback."""
    raw = value if isinstance(value, dict) else {}
    assignments: dict[str, str] = {}
    for role in CYBER_SECURITY_AGENT_ROLES:
        route = _canonical_agent_route(raw.get(role), enabled_routes)
        assignments[role] = (
            route
            if (
                route in enabled_routes
                and _model_route_identity(route, settings)
                != _model_route_identity(primary_assignments.get(role), settings)
            )
            else ""
        )
    return assignments


def normalize_soc_ai_settings(payload: dict | None) -> tuple[bool, dict]:
    """Validate and normalize editable SOC AI model routing settings."""
    payload = payload if isinstance(payload, dict) else {}
    settings = default_soc_ai_settings()
    for key in settings:
        if key in {
            "enabled_ollama_models",
            "codex_cli_models",
            "gpt_cli_enabled",
            "hermes_agent_enabled",
            "openclaw_enabled",
            "agent_models",
            "agent_second_opinion_models",
        }:
            continue
        if key in payload:
            settings[key] = str(payload.get(key) or "").strip()
    # Migrate the original City-only setting without retaining an ambiguous key
    # in newly written runtime configuration.
    city_key = MAXMIND_GEOIP_DATABASE_SETTINGS["city"][0]
    if city_key not in payload and payload.get("maxmind_geoip_db_path") is not None:
        settings[city_key] = str(payload.get("maxmind_geoip_db_path") or "").strip()
    legacy_mode = str(payload.get("mode") or settings["mode"]).strip().lower()
    if legacy_mode not in {"ollama", "cloud", "hybrid"}:
        legacy_mode = "ollama"
    if "enabled_ollama_models" in payload:
        enabled_ollama_models = _normalized_model_list(payload.get("enabled_ollama_models"))
    else:
        legacy_model = str(payload.get("ollama_model") or settings["ollama_model"]).strip()
        enabled_ollama_models = [] if legacy_mode == "cloud" else _normalized_model_list([legacy_model])
    legacy_gpt_enabled = (
        _boolean_setting(payload.get("gpt_cli_enabled"))
        if "gpt_cli_enabled" in payload
        else legacy_mode in {"cloud", "hybrid"}
    )
    if not settings["ollama_url"].startswith(("http://", "https://")):
        return False, {"ok": False, "error": "Ollama URL must start with http:// or https://."}
    codex_cli_path = str(settings.get("codex_cli_path") or "codex").strip()
    codex_cli_model = str(
        payload.get("codex_cli_model")
        or payload.get("cloud_model")
        or settings.get("codex_cli_model")
        or "gpt-5.5"
    ).strip()
    codex_cli_effort = str(
        settings.get("codex_cli_reasoning_effort") or "medium"
    ).strip().lower()
    if not _valid_cli_executable_path(codex_cli_path, "codex"):
        return False, {
            "ok": False,
            "error": "Codex CLI path must be 'codex' or an absolute path ending in /codex.",
        }
    if not _valid_provider_model(codex_cli_model):
        return False, {"ok": False, "error": "Codex CLI model is invalid."}
    if codex_cli_effort not in CODEX_CLI_REASONING_EFFORTS:
        return False, {
            "ok": False,
            "error": "Codex CLI reasoning effort must be low, medium, high, or xhigh.",
        }
    valid_codex_models, codex_cli_models = _normalize_codex_cli_models(
        payload.get("codex_cli_models") if "codex_cli_models" in payload else None,
        legacy_model=codex_cli_model,
        legacy_effort=codex_cli_effort,
        legacy_enabled=legacy_gpt_enabled,
    )
    if not valid_codex_models:
        return False, {
            "ok": False,
            "error": (
                "Codex CLI settings must use each supported catalog model at most "
                "once with a valid reasoning effort."
            ),
        }
    gpt_cli_enabled = any(entry["enabled"] for entry in codex_cli_models)
    hermes_agent_enabled = _boolean_setting(payload.get("hermes_agent_enabled"))
    hermes_agent_path = str(
        payload.get("hermes_agent_path")
        if "hermes_agent_path" in payload
        else settings["hermes_agent_path"]
    ).strip()
    hermes_agent_model = str(
        payload.get("hermes_agent_model")
        if "hermes_agent_model" in payload
        else settings["hermes_agent_model"]
    ).strip()
    hermes_agent_effort = str(
        payload.get("hermes_agent_reasoning_effort")
        if "hermes_agent_reasoning_effort" in payload
        else settings["hermes_agent_reasoning_effort"]
    ).strip().lower()
    openclaw_enabled = _boolean_setting(payload.get("openclaw_enabled"))
    openclaw_path = str(
        payload.get("openclaw_path")
        if "openclaw_path" in payload
        else settings["openclaw_path"]
    ).strip()
    openclaw_model = str(
        payload.get("openclaw_model")
        if "openclaw_model" in payload
        else settings["openclaw_model"]
    ).strip()
    openclaw_effort = str(
        payload.get("openclaw_reasoning_effort")
        if "openclaw_reasoning_effort" in payload
        else settings["openclaw_reasoning_effort"]
    ).strip().lower()
    for label, executable, basename in (
        ("Hermes Agent", hermes_agent_path, "hermes"),
        ("OpenClaw", openclaw_path, "openclaw"),
    ):
        if not _valid_cli_executable_path(executable, basename):
            return False, {
                "ok": False,
                "error": (
                    f"{label} path must be '{basename}' or an absolute path "
                    f"ending in /{basename}."
                ),
            }
    if hermes_agent_model not in CODEX_CLI_MODEL_CATALOG:
        return False, {
            "ok": False,
            "error": "Hermes Agent model is not in the supported Codex model catalog.",
        }
    if not _valid_openclaw_model(openclaw_model):
        return False, {
            "ok": False,
            "error": (
                "OpenClaw currently supports explicit ollama/<model> routes "
                "only; hosted OpenClaw credentials are not admitted into the "
                "isolated runtime."
            ),
        }
    if (
        openclaw_enabled
        and settings["ollama_url"].rstrip("/")
        not in OPENCLAW_SUPPORTED_OLLAMA_URLS
    ):
        return False, {
            "ok": False,
            "error": (
                "OpenClaw requires the loopback Ollama endpoint "
                "http://127.0.0.1:11434 or http://localhost:11434."
            ),
        }
    if hermes_agent_effort != HERMES_AGENT_REASONING_EFFORT:
        return False, {
            "ok": False,
            "error": (
                "Hermes Agent reasoning effort must be medium because the "
                "installed one-shot CLI does not enforce other effort values."
            ),
        }
    if openclaw_effort not in CODEX_CLI_REASONING_EFFORTS:
        return False, {
            "ok": False,
            "error": (
                "OpenClaw reasoning effort must be low, medium, high, or xhigh."
            ),
        }
    if (
        not enabled_ollama_models
        and not gpt_cli_enabled
        and not hermes_agent_enabled
        and not openclaw_enabled
    ):
        return False, {
            "ok": False,
            "error": (
                "Enable at least one Ollama model, Codex CLI model, "
                "Hermes Agent, or OpenClaw."
            ),
        }
    settings["enabled_ollama_models"] = enabled_ollama_models
    settings["codex_cli_models"] = codex_cli_models
    settings["gpt_cli_enabled"] = gpt_cli_enabled
    settings["hermes_agent_enabled"] = hermes_agent_enabled
    settings["hermes_agent_path"] = hermes_agent_path
    settings["hermes_agent_model"] = hermes_agent_model
    settings["hermes_agent_reasoning_effort"] = hermes_agent_effort
    settings["openclaw_enabled"] = openclaw_enabled
    settings["openclaw_path"] = openclaw_path
    settings["openclaw_model"] = openclaw_model
    settings["openclaw_reasoning_effort"] = openclaw_effort
    settings["mode"] = _derive_model_mode(
        enabled_ollama_models + (["openclaw-local"] if openclaw_enabled else []),
        (
            gpt_cli_enabled
            or hermes_agent_enabled
        ),
    )
    if enabled_ollama_models:
        settings["ollama_model"] = enabled_ollama_models[0]
    enabled_codex = next(
        (entry for entry in codex_cli_models if entry["enabled"]),
        codex_cli_models[0] if codex_cli_models else {
            "model": codex_cli_model,
            "reasoning_effort": codex_cli_effort,
        },
    )
    codex_cli_model = enabled_codex["model"]
    codex_cli_effort = enabled_codex["reasoning_effort"]
    settings["codex_cli_path"] = codex_cli_path
    settings["codex_cli_model"] = codex_cli_model
    settings["codex_cli_reasoning_effort"] = codex_cli_effort
    settings["cloud_provider"] = "codex-cli"
    settings["cloud_model"] = codex_cli_model
    # Retain the key for rolling-deploy compatibility but never persist an
    # operator-supplied command that could turn Settings into shell execution.
    settings["cloud_command"] = ""
    enabled_routes = _enabled_agent_model_routes(
        enabled_ollama_models,
        codex_cli_models,
        hermes_agent_enabled=hermes_agent_enabled,
        hermes_agent_model=hermes_agent_model,
        hermes_agent_reasoning_effort=hermes_agent_effort,
        openclaw_enabled=openclaw_enabled,
        openclaw_model=openclaw_model,
        openclaw_reasoning_effort=openclaw_effort,
    )
    settings["agent_models"] = _normalize_agent_models(
        payload.get("agent_models"),
        enabled_routes,
    )
    settings["agent_second_opinion_models"] = _normalize_agent_second_opinion_models(
        payload.get("agent_second_opinion_models"),
        enabled_routes,
        settings["agent_models"],
        settings,
    )
    for setting_key, label in (
        ("soc_analyst_analysis_min_severity", "automatic AI analysis"),
        ("soc_analyst_pcap_min_severity", "PCAP analysis"),
        ("soc_analyst_incident_min_severity", "incident escalation"),
    ):
        threshold = str(settings.get(setting_key) or "").strip().lower()
        if threshold == "info":
            threshold = "informational"
        if threshold not in SOC_ANALYSIS_SEVERITY_THRESHOLDS:
            return False, {
                "ok": False,
                "error": f"SOC Analyst {label} severity threshold is invalid.",
            }
        settings[setting_key] = threshold
    for database_type, (setting_key, _) in MAXMIND_GEOIP_DATABASE_SETTINGS.items():
        geoip_path = settings[setting_key]
        label = database_type.upper() if database_type == "asn" else database_type.title()
        if len(geoip_path) > 1024 or re.search(r"[\x00-\x1f\x7f]", geoip_path):
            return False, {"ok": False, "error": f"MaxMind GeoIP database path for {label} is invalid."}
        if not geoip_path.startswith(("/", "~/")):
            return False, {"ok": False, "error": f"MaxMind GeoIP database path for {label} must be absolute or start with ~/."}
        if Path(geoip_path).suffix.lower() != ".mmdb":
            return False, {"ok": False, "error": f"MaxMind GeoIP database path for {label} must end in .mmdb."}
    for key in (
        "ollama_model",
        "ollama_url",
        "cloud_provider",
        "cloud_model",
        "cloud_command",
        "codex_cli_model",
        "codex_cli_reasoning_effort",
        "hermes_agent_model",
        "hermes_agent_reasoning_effort",
        "openclaw_model",
        "openclaw_reasoning_effort",
    ):
        settings[key] = settings[key][:240]
    return True, settings


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
    """Atomically update one agent's primary and optional secondary routes."""
    payload = payload if isinstance(payload, dict) else {}
    role = str(payload.get("role") or "").strip()
    model_route = str(payload.get("model_route") or payload.get("model") or "").strip()[:260]
    second_model_route = str(
        payload.get("second_opinion_model_route")
        or payload.get("second_opinion_model")
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
        current["agent_models"][role] = model_route
        current["agent_second_opinion_models"][role] = second_model_route
        ok, normalized = normalize_soc_ai_settings(current)
        if not ok:
            return False, normalized
        saved, response = _write_soc_ai_settings(normalized)
        if saved:
            response["message"] = f"Model assignment saved for {role}."
            response["role"] = role
            response["model_route"] = normalized["agent_models"][role]
            response["second_opinion_model_route"] = normalized["agent_second_opinion_models"][role]
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


def latest_threat_report(reports: list[Report]) -> Report | None:
    """Return the newest real threat-intel brief, excluding the index/latest redirect shim."""
    candidates = [r for r in reports if r.category == "Threat Intel" and not r.is_index]
    return max(candidates, key=lambda r: (r.mtime, r.title.lower()), default=None)


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
    token = ensure_admin_token()
    active_action = running_admin_action()
    latest_outcome = None if active_action else latest_admin_action_outcome()
    service_statuses = admin_service_statuses()

    def render_service_card(service_id: str) -> str:
        service = service_statuses[service_id]
        running = bool(service.get("running"))
        level = str(service.get("level") or ("ok" if running else "warn"))
        class_name = "ok" if level == "ok" else ("alert" if level == "alert" else "warn")
        startable = bool(service.get("startable", True))
        button_html = "" if running or not startable else f'<button class="service-start-button" type="button" data-start-service="{html.escape(service_id)}">Start</button>'
        return f'''
  <div class="admin-indicator {class_name}" data-service-card="{html.escape(service_id)}" data-running="{str(running).lower()}" data-level="{html.escape(level)}">
    <div class="admin-indicator-top"><span>{html.escape(str(service.get('label', service_id)))}</span>{button_html}</div>
    <strong>{html.escape(str(service.get('value', 'Unknown')))}</strong>
    <small>{html.escape(str(service.get('detail', 'No detail available.')))}</small>
  </div>'''

    fan_status_html = f'''
<section class="admin-status-grid">
{render_service_card('macs-fan-control')}
{render_service_card('codex')}
{render_service_card('codex-cli')}
{render_service_card('docker')}
{render_service_card('n8n')}
</section>'''
    cards: list[str] = []
    log_sections: list[str] = []
    for action_id, action in ADMIN_ACTIONS.items():
        status = read_admin_action_status(action_id)
        state = str(status.get("state") or "idle")
        display_state = "completed" if state == "ok" else state
        badge_class = "warn" if state in {"failed", "error", "unknown"} else ""
        command_text = " ".join(str(part) for part in action["command"])
        last_performed, last_performed_detail = admin_last_performed_label(status)
        available, availability_message = check_admin_action_available(action_id, skip_expensive=bool(active_action))
        version_info = admin_action_version_info(action_id)
        is_reboot = action_id == "reboot"
        confirm_html = ""
        button_label = "Approve update"
        form_attrs = ""
        disabled_attr = " disabled" if active_action or (not is_reboot and not available) else ""
        if is_reboot:
            button_label = "Reboot system"
            confirm_html = '<label class="confirm-label">Type <code>REBOOT</code> to confirm<input name="confirmation" autocomplete="off" placeholder="REBOOT" /></label>'
            form_attrs = ' data-reboot-form="true"'
        if active_action:
            button_label = "Wait for running action"
        elif not is_reboot and not available:
            button_label = "No updates available"
        cards.append(f'''
<section class="admin-card" style="--admin-accent:{html.escape(str(action.get('accent', '#23d3ee')))}">
  <div class="admin-card-top"><div><span class="section-label">Action</span><h2>{html.escape(str(action['label']))}</h2></div><span class="badge {badge_class}">{html.escape(display_state)}</span></div>
  <p>{html.escape(str(action.get('summary', '')))}</p>
  <div class="admin-action-metric" title="{html.escape(last_performed_detail)}"><span>Last performed</span><strong>{html.escape(last_performed)}</strong><small>{html.escape(last_performed_detail)}</small></div>
  <div class="admin-version-grid">
    <div class="admin-version-metric" title="{html.escape(str(version_info.get('detail') or ''))}"><span>Current version</span><strong>{html.escape(str(version_info.get('current') or 'Unknown'))}</strong></div>
    <div class="admin-version-metric latest" title="{html.escape(str(version_info.get('detail') or ''))}"><span>Latest available</span><strong>{html.escape(str(version_info.get('latest') or 'Unknown'))}</strong></div>
  </div>
  <table><tbody>
    <tr><th>Last message</th><td>{html.escape(str(status.get('message') or 'Not run yet.'))}</td></tr>
    <tr><th>Availability</th><td><span class="badge {'' if available else 'warn'}">{html.escape('Available' if available else 'Unavailable')}</span> {html.escape(availability_message)}</td></tr>
    <tr><th>Version detail</th><td>{html.escape(str(version_info.get('detail') or 'No version detail available.'))}</td></tr>
    <tr><th>Started</th><td>{html.escape(str(status.get('started_at') or 'Not run yet.'))}</td></tr>
    <tr><th>PID / return code</th><td>{html.escape(str(status.get('pid') or '—'))} / {html.escape(str(status.get('returncode') if status.get('returncode') is not None else '—'))}</td></tr>
    <tr><th>Command</th><td><code>{html.escape(command_text)}</code></td></tr>
  </tbody></table>
  <form method="post" action="/admin/action"{form_attrs}>
    <input type="hidden" name="token" value="{html.escape(token)}" />
    <input type="hidden" name="action" value="{html.escape(action_id)}" />
    {confirm_html}
    <button class="admin-button {'danger' if is_reboot else ''}" type="submit"{disabled_attr}>{html.escape(button_label)}</button>
  </form>
</section>''')
        log_sections.append(f'''
<section class="section"><h2>{html.escape(str(action['label']))} log tail</h2><pre>{html.escape(tail_file(admin_log_path(action_id)))}</pre></section>''')
    try:
        admin_action_files = sorted(
            [p for p in ADMIN_STATE_DIR.iterdir() if p.is_file()],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    except Exception:
        admin_action_files = []
    admin_action_rows = "".join(
        f"<tr><td><code>{html.escape(path.name)}</code></td>"
        f"<td>{html.escape(human_size(path.stat().st_size))}</td>"
        f"<td>{html.escape(format_iso_timestamp(dt.datetime.fromtimestamp(path.stat().st_mtime).astimezone()))}</td></tr>"
        for path in admin_action_files
    ) or '<tr><td colspan="3">No files found in the Administration action directory.</td></tr>'
    log_sections.insert(0, f'''
<section class="section"><h2>Administration action directory</h2><p>Local action status and logs live under <code>{html.escape(str(ADMIN_STATE_DIR))}</code>.</p><table><thead><tr><th>File</th><th>Size</th><th>Modified</th></tr></thead><tbody>{admin_action_rows}</tbody></table></section>''')
    log_sections.insert(1, render_cron_failure_log_section())
    message_html = ""
    if active_action:
        message_html += f'<section class="section"><span class="badge warn">Action running</span><p>{html.escape(str(active_action.get("label", "An admin action")))} is currently running as PID {html.escape(str(active_action.get("pid", "unknown")))}. Additional updates and reboot are disabled until it completes.</p></section>'
    elif latest_outcome:
        outcome_state = str(latest_outcome.get("state") or "unknown")
        outcome_ok = outcome_state == "ok"
        outcome_badge = "Action completed" if outcome_ok else "Action failed"
        outcome_class = "" if outcome_ok else "warn"
        rc_text = "" if latest_outcome.get("returncode") is None else f" Return code: {latest_outcome.get('returncode')}."
        outcome_message = f'{latest_outcome.get("label", "Admin action")} {"completed successfully" if outcome_ok else "failed"} at {latest_outcome.get("when", "unknown time")}. {latest_outcome.get("message", "")}{rc_text}'
        message_html += f'<section class="section"><span class="badge {outcome_class}">{html.escape(outcome_badge)}</span><p>{html.escape(outcome_message)}</p></section>'
    if message:
        message_html += f'<section class="section"><span class="badge {"warn" if error else ""}">{"Action blocked" if error else "Action started"}</span><p>{html.escape(message)}</p></section>'
    body = f'''
<style>
.admin-status-grid {{ display:grid; grid-template-columns:repeat(5, minmax(0,1fr)); gap:14px; margin:18px 0 }}
.admin-indicator {{ --indicator-accent:#28e0a6; position:relative; border:1px solid color-mix(in srgb, var(--indicator-accent) 28%, rgba(148,163,184,.16)); border-radius:22px; padding:18px; background:linear-gradient(145deg, color-mix(in srgb, var(--indicator-accent) 10%, rgba(18,26,41,.94)), rgba(10,16,27,.90)); box-shadow:0 14px 40px rgba(0,0,0,.18) }}
.admin-indicator.warn {{ --indicator-accent:#f8c76a }}
.admin-indicator.alert {{ --indicator-accent:#ff7a90 }}
.admin-indicator-top {{ display:flex; align-items:flex-start; justify-content:space-between; gap:12px; margin-bottom:7px }}
.admin-indicator span {{ display:block; color:color-mix(in srgb, var(--indicator-accent) 50%, #9bdff2); font-size:10px; letter-spacing:.13em; text-transform:uppercase; font-weight:950 }}
.service-start-button {{ flex:0 0 auto; border:1px solid color-mix(in srgb, var(--indicator-accent) 38%, rgba(255,255,255,.18)); border-radius:999px; padding:7px 10px; color:#061018; background:linear-gradient(135deg, var(--indicator-accent), #23d3ee); font-size:11px; font-weight:950; cursor:pointer; box-shadow:0 10px 24px rgba(0,0,0,.16) }}
.service-start-button:disabled {{ cursor:wait; opacity:.55; filter:saturate(.55); color:#dbeafe; background:linear-gradient(135deg, #64748b, #334155) }}
.admin-indicator strong {{ display:block; color:#f8fbff; font-size:clamp(24px,3.4vw,40px); line-height:1; letter-spacing:-.05em }}
.admin-indicator small {{ display:block; margin-top:8px; color:#aebbd0; font-size:12px; line-height:1.4; overflow-wrap:anywhere }}
.admin-grid {{ display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:14px; margin:18px 0 }}
.admin-card {{ position:relative; overflow:hidden; border:1px solid color-mix(in srgb, var(--admin-accent) 26%, rgba(148,163,184,.16)); border-radius:22px; background:linear-gradient(145deg, color-mix(in srgb, var(--admin-accent) 10%, rgba(18,26,41,.94)), rgba(10,16,27,.90)); padding:18px; box-shadow:0 14px 40px rgba(0,0,0,.18) }}
.admin-card:before {{ content:""; position:absolute; inset:0 0 auto 0; height:4px; background:linear-gradient(90deg, var(--admin-accent), rgba(148,163,184,.32)) }}
.admin-card-top {{ display:flex; align-items:flex-start; justify-content:space-between; gap:12px }}
.admin-card h2 {{ margin:0 0 10px }}
.admin-action-metric {{ margin:14px 0; border:1px solid color-mix(in srgb, var(--admin-accent) 24%, rgba(148,163,184,.14)); border-radius:18px; padding:14px 15px; background:linear-gradient(135deg, color-mix(in srgb, var(--admin-accent) 10%, rgba(15,23,42,.88)), rgba(2,6,23,.36)); box-shadow:inset 0 1px 0 rgba(255,255,255,.045) }}
.admin-action-metric span {{ display:block; color:color-mix(in srgb, var(--admin-accent) 46%, #9bdff2); font-size:10px; letter-spacing:.13em; text-transform:uppercase; font-weight:950; margin-bottom:6px }}
.admin-action-metric strong {{ display:block; color:#f8fbff; font-size:clamp(24px,3.4vw,40px); line-height:1; letter-spacing:-.06em }}
.admin-action-metric small {{ display:block; margin-top:7px; color:#aebbd0; font-size:12px; line-height:1.35; overflow-wrap:anywhere }}
.admin-version-grid {{ display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:10px; margin:14px 0 }}
.admin-version-metric {{ min-width:0; border:1px solid color-mix(in srgb, var(--admin-accent) 18%, rgba(148,163,184,.14)); border-radius:16px; padding:12px; background:rgba(2,6,23,.30) }}
.admin-version-metric.latest {{ background:linear-gradient(135deg, color-mix(in srgb, var(--admin-accent) 9%, rgba(2,6,23,.42)), rgba(2,6,23,.30)) }}
.admin-version-metric span {{ display:block; color:color-mix(in srgb, var(--admin-accent) 44%, #9bdff2); font-size:10px; letter-spacing:.12em; text-transform:uppercase; font-weight:950; margin-bottom:6px }}
.admin-version-metric strong {{ display:block; color:#edf5ff; font-size:13px; line-height:1.28; overflow-wrap:anywhere }}
.admin-card form {{ display:grid; gap:10px; margin-top:14px }}
.confirm-label {{ display:grid; gap:7px; color:#d7e5f8; font-size:13px; font-weight:800 }}
.confirm-label input {{ width:100%; border:1px solid rgba(255,122,144,.38); border-radius:14px; padding:11px 12px; color:#fff; background:rgba(2,6,23,.62); font:inherit }}
.admin-button {{ border:0; border-radius:14px; padding:12px 14px; font-weight:950; color:#061018; background:linear-gradient(135deg, var(--admin-accent), #23d3ee); cursor:pointer }}
.admin-button:disabled {{ cursor:not-allowed; opacity:.48; filter:saturate(.45); background:linear-gradient(135deg, #64748b, #334155); color:#dbeafe }}
.admin-button.danger {{ color:#fff; background:linear-gradient(135deg, #ff7a90, #dc2626) }}
.admin-button.danger:disabled {{ background:linear-gradient(135deg, #64748b, #334155); color:#dbeafe }}
.admin-logout-form {{ margin:0; flex:0 0 auto }}
.admin-logout-button {{ border:1px solid rgba(35,211,238,.32); border-radius:999px; padding:9px 12px; color:#aeeeff; background:rgba(35,211,238,.065); font-weight:950; cursor:pointer }}
.admin-logout-button:hover {{ border-color:rgba(35,211,238,.62); background:rgba(35,211,238,.12) }}
.cron-menu {{ --cron-accent:#7dd3fc; --cron-accent2:#94a3b8; position:relative; margin:18px 0; border:1px solid color-mix(in srgb, var(--cron-accent) 24%, rgba(148,163,184,.16)); border-radius:24px; background:linear-gradient(145deg, color-mix(in srgb, var(--cron-accent) 8%, rgba(18,26,41,.94)), rgba(10,15,25,.91) 62%, color-mix(in srgb, var(--cron-accent2) 7%, rgba(8,12,20,.92))); box-shadow:0 16px 44px rgba(0,0,0,.20), inset 0 1px 0 rgba(255,255,255,.045); overflow:hidden; isolation:isolate }}
.cron-menu:before {{ content:""; position:absolute; inset:0 0 auto 0; height:4px; background:linear-gradient(90deg, color-mix(in srgb, var(--cron-accent) 72%, #64748b), color-mix(in srgb, var(--cron-accent2) 72%, #475569)); opacity:.62 }}
.cron-menu summary {{ min-height:68px; list-style:none; cursor:pointer; display:flex; align-items:center; justify-content:space-between; gap:14px; padding:17px 18px 16px; touch-action:manipulation }}
.cron-menu summary::-webkit-details-marker {{ display:none }}
.cron-summary-main {{ display:flex; align-items:center; gap:12px; min-width:0 }}
.cron-summary-main b {{ display:block; color:#eef6ff; font-size:18px; line-height:1.05; letter-spacing:-.025em }}
.cron-summary-main small {{ display:block; margin-top:5px; color:color-mix(in srgb, var(--cron-accent) 36%, #94a3b8); font-size:11px; font-weight:900; letter-spacing:.1em; text-transform:uppercase }}
.cron-dot {{ width:12px; height:12px; border-radius:999px; background:color-mix(in srgb, var(--green, #28e0a6) 70%, #94a3b8); box-shadow:0 0 18px rgba(40,224,166,.38); flex:0 0 auto }}
.cron-chevron {{ color:#c8d6ea; font-size:24px; line-height:1; transition:transform .16s ease, color .16s ease }}
.cron-menu[open] .cron-chevron {{ transform:rotate(180deg) }}
.cron-panel {{ display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:12px; padding:0 12px 14px }}
.cron-item {{ --job-accent:#7dd3fc; position:relative; overflow:hidden; border:1px solid color-mix(in srgb, var(--job-accent) 20%, rgba(148,163,184,.14)); border-radius:18px; background:linear-gradient(145deg, color-mix(in srgb, var(--job-accent) 7%, rgba(18,26,41,.88)), rgba(10,16,27,.82)); padding:14px; display:grid; gap:10px; box-shadow:0 12px 32px rgba(0,0,0,.16), inset 0 1px 0 rgba(255,255,255,.035) }}
.cron-item:before {{ content:""; position:absolute; inset:0 0 auto 0; height:3px; background:linear-gradient(90deg, color-mix(in srgb, var(--job-accent) 58%, #64748b), rgba(148,163,184,.18)); opacity:.58 }}
.cron-item:nth-child(2n) {{ --job-accent:#a78bfa }}
.cron-item:nth-child(3n) {{ --job-accent:#28e0a6 }}
.cron-item:nth-child(4n) {{ --job-accent:#f8c76a }}
.cron-item.disabled {{ --job-accent:#94a3b8; opacity:.72; background:linear-gradient(145deg, rgba(18,26,41,.62), rgba(10,16,27,.58)) }}
.cron-item-top {{ display:flex; align-items:flex-start; justify-content:space-between; gap:10px }}
.cron-item-top strong {{ color:#edf5ff; font-size:15px; line-height:1.25; letter-spacing:-.01em }}
.cron-status {{ flex:0 0 auto; font-size:10px; font-weight:950; text-transform:uppercase; letter-spacing:.09em; border-radius:999px; padding:5px 8px; border:1px solid rgba(40,224,166,.20); color:#a8f1dc; background:rgba(40,224,166,.065) }}
.cron-status.disabled {{ color:#e8c989; background:rgba(248,199,106,.055); border-color:rgba(248,199,106,.18) }}
.cron-next {{ display:grid; gap:4px; border-radius:14px; padding:10px 12px; background:color-mix(in srgb, var(--job-accent) 7%, rgba(255,255,255,.025)); border:1px solid color-mix(in srgb, var(--job-accent) 15%, rgba(148,163,184,.12)) }}
.cron-next span,.cron-section-label {{ color:color-mix(in srgb, var(--job-accent) 32%, #94a3b8); font-size:10px; text-transform:uppercase; letter-spacing:.11em; font-weight:950 }}
.cron-next b {{ color:#f4f8ff; font-size:15px; line-height:1.12 }}
.cron-meta {{ display:flex; flex-wrap:wrap; gap:7px; color:#aebbd0; font-size:11px }}
.cron-meta span {{ border:1px solid color-mix(in srgb, var(--job-accent) 12%, rgba(148,163,184,.13)); background:rgba(255,255,255,.022); border-radius:999px; padding:5px 7px }}
.cron-disabled {{ display:grid; grid-column:1/-1; gap:10px; margin-top:2px; padding-top:12px; border-top:1px dashed rgba(148,163,184,.18) }}
.cron-empty {{ color:var(--muted, #8b98ac); padding:16px; text-align:center }}
.cron-failure-log table code {{ white-space:normal; word-break:break-word }}
.cron-failure-detail {{ margin-top:12px; border:1px solid rgba(248,199,106,.22); border-radius:16px; background:rgba(248,199,106,.045); overflow:hidden }}
.cron-failure-detail summary {{ cursor:pointer; padding:12px 14px; color:#ffdfa3; font-weight:900; line-height:1.35 }}
.cron-failure-detail pre {{ margin:0; border-top:1px solid rgba(248,199,106,.16); border-radius:0; max-height:460px; overflow:auto }}
@media (max-width:900px) {{ .admin-grid {{ grid-template-columns:1fr }} .admin-status-grid {{ grid-template-columns:1fr }} .cron-panel {{ grid-template-columns:1fr }} }}
</style>
{fan_status_html}
{render_cron_menu()}
{message_html}
<section class="admin-grid">{''.join(cards)}</section>
{''.join(log_sections)}
<script>
const adminServiceToken = {json.dumps(token)};
function updateServiceCard(service) {{
  const card = document.querySelector(`[data-service-card="${{service.id}}"]`);
  if (!card) return;
  const level = service.level || (service.running ? 'ok' : 'warn');
  const startable = service.startable !== false;
  card.dataset.running = service.running ? 'true' : 'false';
  card.dataset.level = level;
  card.classList.toggle('ok', level === 'ok');
  card.classList.toggle('warn', level !== 'ok' && level !== 'alert');
  card.classList.toggle('alert', level === 'alert');
  const value = card.querySelector('strong');
  const detail = card.querySelector('small');
  const top = card.querySelector('.admin-indicator-top');
  if (value) value.textContent = service.value || (service.running ? 'Running' : 'Not running');
  if (detail) detail.textContent = service.detail || '';
  const existing = card.querySelector('[data-start-service]');
  if (service.running || !startable) {{
    if (existing) existing.remove();
  }} else if (!existing && top) {{
    const button = document.createElement('button');
    button.className = 'service-start-button';
    button.type = 'button';
    button.dataset.startService = service.id;
    button.textContent = 'Start';
    top.appendChild(button);
  }} else if (existing) {{
    existing.disabled = false;
    existing.textContent = 'Start';
  }}
}}
async function refreshServiceStatuses() {{
  const response = await fetch('/api/admin/service-status', {{cache: 'no-store', credentials: 'same-origin'}});
  if (!response.ok) throw new Error(`Status check failed: ${{response.status}}`);
  const data = await response.json();
  Object.values(data.services || {{}}).forEach(updateServiceCard);
  return data.services || {{}};
}}
async function pollServiceUntilRunning(serviceId, button) {{
  for (let attempt = 0; attempt < 30; attempt += 1) {{
    const services = await refreshServiceStatuses();
    if (services[serviceId] && services[serviceId].running) return true;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }}
  if (button && document.body.contains(button)) {{
    button.disabled = false;
    button.textContent = 'Start';
  }}
  return false;
}}
document.addEventListener('click', async (event) => {{
  const button = event.target.closest('[data-start-service]');
  if (!button) return;
  event.preventDefault();
  const serviceId = button.dataset.startService;
  button.disabled = true;
  button.textContent = 'Starting…';
  try {{
    const response = await fetch('/api/admin/start-service', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      credentials: 'same-origin',
      body: JSON.stringify({{token: adminServiceToken, service: serviceId}})
    }});
    const data = await response.json().catch(() => ({{ok:false, error:'Invalid JSON response'}}));
    if (data.service) updateServiceCard(data.service);
    if (!response.ok || !data.ok) throw new Error(data.error || data.message || `Start failed: ${{response.status}}`);
    button.textContent = 'Checking…';
    await pollServiceUntilRunning(serviceId, button);
  }} catch (error) {{
    const card = document.querySelector(`[data-service-card="${{serviceId}}"]`);
    const detail = card ? card.querySelector('small') : null;
    if (detail) detail.textContent = `WARNING: ${{error.message}}`;
    if (button && document.body.contains(button)) {{
      button.disabled = false;
      button.textContent = 'Start';
    }}
  }}
}});
document.querySelectorAll('form[data-reboot-form="true"]').forEach((form) => {{
  form.addEventListener('submit', (event) => {{
    const input = form.querySelector('input[name="confirmation"]');
    if (!input || input.value !== 'REBOOT') {{
      event.preventDefault();
      alert('Type REBOOT to confirm before rebooting.');
      return;
    }}
    if (!confirm('Reboot this Mac now? This will interrupt running tasks.')) {{
      event.preventDefault();
    }}
  }});
}});
const adminActionRunning = {"true" if active_action else "false"};
if (adminActionRunning) {{
  setTimeout(() => window.location.reload(), 5000);
}}
</script>'''
    hero_logout = f'<form class="admin-logout-form" method="post" action="/admin/logout"><input type="hidden" name="token" value="{html.escape(token)}" /><button class="admin-logout-button" type="submit">Sign out</button></form>'
    return metric_detail_shell("⚙️ Administration", "System administration", body, hero_logout)


def render_home(reports: list[Report], host: str, port: int) -> bytes:
    system_uptime_value, system_uptime_detail, system_uptime_warning = system_uptime_metric()
    system_uptime_class = " stat-alert" if system_uptime_warning else " stat-ok"
    portal_updated_ts = portal_last_updated(reports)
    updates_value, updates_detail, updates_count, updates_source = prioritized_updates_metric()
    updates_class = " stat-alert" if updates_count != 0 else " stat-ok"
    hermes_backup_value, hermes_backup_detail, hermes_backup_warning = latest_hermes_backup_metric()
    hermes_backup_class = " stat-alert" if hermes_backup_warning else ""
    local_free_space, local_disk_total, local_disk_percent_free = local_disk_usage_metric()
    local_disk_class = " stat-alert" if local_disk_percent_free <= 20.0 else " stat-ok"
    local_disk_detail = f"{human_size(local_free_space)} free of {human_size(local_disk_total)} total · {local_disk_percent_free:.1f}% free"
    portal_update_warning = False
    portal_update_value = "None"
    portal_update_detail = "No portal update timestamp recorded."
    if portal_updated_ts:
        portal_update_dt = dt.datetime.fromtimestamp(portal_updated_ts).astimezone()
        portal_update_age_seconds = max(0.0, (dt.datetime.now().astimezone() - portal_update_dt).total_seconds())
        portal_update_warning = portal_update_age_seconds > 3600
        portal_update_age_minutes = int(portal_update_age_seconds // 60)
        portal_update_value = relative_time_label(portal_updated_ts)
        portal_update_detail = f"Latest portal update: {format_iso_timestamp(portal_update_dt)} · {portal_update_age_minutes} minutes ago"
    portal_update_class = " stat-alert" if portal_update_warning else ""
    llm_dashboard = next((r for r in reports if "Local LLM Benchmark Dashboard" in r.title or "Local LLM Benchmark Dashboard" in r.rel), None)
    athf_dashboard = next((r for r in reports if "Threat Hunt Command Center" in r.title or "Threat Hunting/ATHF/index.html" in r.rel), None)
    daily_threat_dashboard = next((r for r in reports if "Daily Threat Brief Dashboard" in r.title or "Threat Intel/index.html" in r.rel), None)
    event_radar = next((r for r in reports if r.title == "Cyber Security Event Radar" or "Cybersecurity/Cyber Security Event Radar/index.html" in r.rel), None)
    osquery_dashboard = next((r for r in reports if "Elastic Osquery Threat Hunting Cheatsheet" in r.title or "Elastic Osquery Threat Hunting Cheatsheet" in r.rel), None)
    kql_oql_mitre_dashboard = next((r for r in reports if "Elastic KQL and Security Onion OQL MITRE ATT&CK Mapping" in r.title or "KQL_OQL_Mapped_to_Mitre/MITRE_KQL_Mapping_Portable.html" in r.rel), None)
    soc_alerts_dashboard = soc_alerts_report(reports)
    sigma_guide = next((r for r in reports if r.title == "Sigma Detection Engineering Guide" or "Sigma Detection Engineering Guide/index.html" in r.rel), None)
    pdf_library = next((r for r in reports if r.title in ("Cybersecurity Library", "Resource Library") or "Cybersecurity Library/index.html" in r.rel or "Resource Library/index.html" in r.rel), None)
    product_research_dashboard = next((r for r in reports if r.title == "Product Research Dashboard" or "Product Research/index.html" in r.rel), None)
    web_app_projects_dashboard = next((r for r in reports if r.title == "Web App Projects Dashboard" or "Web App Projects/index.html" in r.rel), None)
    portal_architecture = next((r for r in reports if "LAN Portal Web Server Architecture" in r.title or "LAN Portal Web Server Architecture" in r.rel), None)
    quick_cards = []
    cyber_cards = []
    if soc_alerts_dashboard:
        cyber_cards.append(f'''
      <a class="app-card" href="/view/{soc_alerts_dashboard.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">🚨</span>
        <span><b>SOC Alerts</b><span>Security Onion alert automation reports and detailed network findings</span></span>
      </a>''')
    if athf_dashboard:
        cyber_cards.append(f'''
      <a class="app-card" href="/view/{athf_dashboard.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">🛡️</span>
        <span><b>ATHF Command Center</b><span>Threat hunts, ATT&CK coverage, CQL, and Elastic KQL</span></span>
      </a>''')
    if daily_threat_dashboard:
        cyber_cards.append(f'''
      <a class="app-card" href="/view/{daily_threat_dashboard.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">🛰️</span>
        <span><b>Daily Threat Briefs</b><span>Standalone CTI dashboard and searchable brief archive</span></span>
      </a>''')
    if event_radar:
        cyber_cards.append(f'''
      <a class="app-card" data-permanent-artifact="cyber-security-event-radar" href="/view/{event_radar.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">📡</span>
        <span><b>Cyber Security Event Radar</b><span>Denver metro cybersecurity events over the next six months</span></span>
      </a>''')
    if osquery_dashboard:
        cyber_cards.append(f'''
      <a class="app-card" href="/view/{osquery_dashboard.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">🧬</span>
        <span><b>Elastic Osquery Cheatsheet</b><span>Windows, macOS, and Linux endpoint hunt queries</span></span>
      </a>''')
    if kql_oql_mitre_dashboard:
        cyber_cards.append(f'''
      <a class="app-card" href="/view/{kql_oql_mitre_dashboard.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">🧭</span>
        <span><b>KQL/OQL MITRE Map</b><span>Elastic KQL and Security Onion OQL mapped to ATT&CK</span></span>
      </a>''')
    if sigma_guide:
        cyber_cards.append(f'''
      <a class="app-card" href="/view/{sigma_guide.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">Σ</span>
        <span><b>Sigma Guide</b><span>Detection engineering, threat hunting, sigma-cli, and rule tuning</span></span>
      </a>''')
    if pdf_library:
        cyber_cards.append(f'''
      <a class="app-card" href="/view/{pdf_library.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">📚</span>
        <span><b>Cybersecurity Library</b><span>Books, talk slides, posters, tools, certificates, and cybersecurity cheatsheets</span></span>
      </a>''')
    if product_research_dashboard:
        quick_cards.append(f'''
      <a class="app-card" href="/view/{product_research_dashboard.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">📈</span>
        <span><b>Product Research</b><span>Searchable entrepreneurial product research report archive</span></span>
      </a>''')
    if web_app_projects_dashboard:
        quick_cards.append(f'''
      <a class="app-card" href="/view/{web_app_projects_dashboard.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">🧩</span>
        <span><b>Web App Projects</b><span>Interactive prototypes and project demos hosted on the LAN Portal</span></span>
      </a>''')
    if portal_architecture:
        quick_cards.append(f'''
      <a class="app-card" href="/view/{portal_architecture.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">🧭</span>
        <span><b>Portal Architecture</b><span>Web server upgrade triggers, SQLite guidance, and migration path</span></span>
      </a>''')
    if llm_dashboard:
        quick_cards.append(f'''
      <a class="app-card" href="/view/{llm_dashboard.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">🧠</span>
        <span><b>LLM Dashboard</b><span>Local Ollama/OpenClaw inventory and benchmarks</span></span>
      </a>''')
    mobile_apps_html = ""
    if quick_cards:
        mobile_apps_html = f'''
  <section class="mobile-apps" aria-label="Portal links">
    <h2>Portal Links</h2>
    <div class="app-strip">{''.join(quick_cards)}
    </div>
  </section>'''
    cyber_portal_html = ""
    if cyber_cards:
        cyber_portal_html = f'''
  <section class="mobile-apps cyber-portal" aria-label="Cyber Portal">
    <h2>Cyber Portal</h2>
    <div class="app-strip">{''.join(cyber_cards)}
    </div>
  </section>'''
    page = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Mac Studio LAN Portal</title>
<style>
:root {{
  --bg:#080b12; --panel:#0e1420; --panel2:#121a29; --muted:#8b98ac; --text:#edf3ff;
  --line:rgba(148,163,184,.18); --cyan:#23d3ee; --blue:#4f8cff; --green:#28e0a6; --amber:#f8c76a;
  --shadow:0 24px 80px rgba(0,0,0,.42); --radius:22px;
}}
* {{ box-sizing:border-box }}
body {{ margin:0; font-family:Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color:var(--text); background:
  radial-gradient(circle at 14% -10%, rgba(35,211,238,.22), transparent 38%),
  radial-gradient(circle at 90% 4%, rgba(79,140,255,.18), transparent 34%),
  linear-gradient(180deg, #080b12 0%, #0a0f19 48%, #070910 100%); min-height:100vh; }}
a {{ color:inherit; text-decoration:none }}
.shell {{ width:min(1280px, calc(100% - 32px)); margin:0 auto; padding:26px 0 50px }}
.hero {{ border:1px solid var(--line); background:linear-gradient(135deg, rgba(18,26,41,.92), rgba(8,11,18,.84)); border-radius:26px; padding:22px 24px; box-shadow:var(--shadow); position:relative; overflow:hidden }}
.hero:after {{ content:""; position:absolute; inset:auto -80px -160px auto; width:300px; height:300px; background:radial-gradient(circle, rgba(40,224,166,.16), transparent 68%); pointer-events:none }}
.hero-row {{ position:relative; z-index:2; display:flex; align-items:center; justify-content:space-between; gap:14px }}
.hero-refresh {{ --refresh-accent:#23d3ee; --refresh-glow:rgba(35,211,238,.42); flex:0 0 auto; width:56px; height:56px; min-width:56px; min-height:56px; display:inline-flex; align-items:center; justify-content:center; border:1px solid rgba(35,211,238,.56); border-radius:22px; padding:0; color:var(--refresh-accent); background:linear-gradient(145deg, rgba(14,24,38,.78), rgba(7,15,25,.92)); box-shadow:0 16px 38px rgba(0,0,0,.28), inset 0 1px 0 rgba(255,255,255,.045), inset 0 -14px 30px rgba(6,12,22,.36), 0 0 0 1px rgba(35,211,238,.035); cursor:pointer; touch-action:manipulation; -webkit-tap-highlight-color:transparent; transition:transform .16s ease, border-color .16s ease, box-shadow .2s ease, filter .16s ease, background .2s ease; position:relative; overflow:hidden }}
.hero-refresh:before {{ content:""; position:absolute; inset:1px; border:1px solid rgba(35,211,238,.18); border-radius:20px; background:radial-gradient(circle at 50% 45%, rgba(35,211,238,.10), transparent 58%); box-shadow:inset 0 0 20px rgba(35,211,238,.06); pointer-events:none }}
.hero-refresh:after {{ content:""; position:absolute; inset:auto -24px -34px -24px; height:58%; background:radial-gradient(ellipse at 50% 100%, rgba(35,211,238,.10), transparent 66%); pointer-events:none }}
.hero-refresh:hover {{ transform:translateY(-1px); border-color:rgba(35,211,238,.95); background:linear-gradient(145deg, rgba(16,31,46,.88), rgba(7,15,25,.94)); box-shadow:0 22px 54px rgba(0,0,0,.34), 0 0 18px rgba(35,211,238,.42), 0 0 44px rgba(35,211,238,.24), 0 0 76px rgba(35,211,238,.14), inset 0 1px 0 rgba(255,255,255,.065), inset 0 0 24px rgba(35,211,238,.08) }}
.hero-refresh:hover:before {{ border-color:rgba(35,211,238,.34); box-shadow:inset 0 0 28px rgba(35,211,238,.12), 0 0 18px rgba(35,211,238,.12) }}
.hero-refresh:active {{ transform:translateY(1px) scale(.99) }}
.hero-refresh[aria-busy="true"], .hero-refresh.refreshing {{ cursor:wait; filter:saturate(1.18); border-color:rgba(35,211,238,1); box-shadow:0 22px 56px rgba(0,0,0,.34), 0 0 22px rgba(35,211,238,.52), 0 0 56px rgba(35,211,238,.30), 0 0 88px rgba(35,211,238,.18), inset 0 1px 0 rgba(255,255,255,.08), inset 0 0 28px rgba(35,211,238,.10) }}
.hero-refresh-icon {{ position:relative; z-index:1; display:block; font-size:31px; line-height:1; transform-origin:center; color:var(--refresh-accent); text-shadow:0 0 10px rgba(35,211,238,.35), 0 0 24px rgba(35,211,238,.20) }}
.hero-refresh:hover .hero-refresh-icon {{ text-shadow:0 0 12px rgba(35,211,238,.62), 0 0 30px rgba(35,211,238,.34), 0 0 54px rgba(35,211,238,.18) }}
.hero-refresh[aria-busy="true"] .hero-refresh-icon, .hero-refresh.refreshing .hero-refresh-icon {{ animation:refresh-spin .72s linear infinite }}
@keyframes refresh-spin {{ to {{ transform:rotate(360deg) }} }}
.kicker {{ display:inline-flex; gap:8px; align-items:center; color:var(--cyan); font-size:12px; letter-spacing:.16em; text-transform:uppercase; font-weight:800 }}
h1 {{ font-size:clamp(30px, 4.4vw, 54px); line-height:.96; letter-spacing:-.055em; margin:10px 0 2px }}
.subtitle {{ color:#b7c4d8; max-width:820px; font-size:17px; line-height:1.65; margin:0 }}
.urls {{ display:flex; flex-wrap:wrap; gap:10px; margin-top:22px }}
.urlpill {{ font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:13px; border:1px solid var(--line); background:rgba(15,23,42,.72); color:#d9e6f7; padding:10px 12px; border-radius:999px }}
.stats {{ display:grid; grid-template-columns:repeat(5, minmax(0,1fr)); gap:14px; margin:18px 0 16px }}
.stat {{ --accent:var(--cyan); --accent2:var(--green); position:relative; overflow:hidden; min-width:0; background:linear-gradient(145deg, color-mix(in srgb, var(--accent) 14%, rgba(18,26,41,.94)), rgba(10,16,27,.90) 58%, color-mix(in srgb, var(--accent2) 9%, rgba(8,12,20,.92))); border:1px solid color-mix(in srgb, var(--accent) 34%, rgba(148,163,184,.16)); border-radius:22px; padding:17px 16px 18px; box-shadow:0 16px 44px rgba(0,0,0,.22), inset 0 1px 0 rgba(255,255,255,.055); display:flex; flex-direction:column; gap:8px; isolation:isolate; transition:transform .16s ease, border-color .16s ease, box-shadow .16s ease; color:inherit; text-decoration:none; cursor:pointer }}
.stat:before {{ content:""; position:absolute; inset:0 0 auto 0; height:4px; background:linear-gradient(90deg, var(--accent), var(--accent2)); opacity:.95 }}
.stat:after {{ content:""; position:absolute; width:120px; height:120px; right:-58px; top:-58px; border-radius:999px; background:radial-gradient(circle, color-mix(in srgb, var(--accent) 28%, transparent), transparent 68%); filter:blur(.2px); opacity:.78; z-index:-1 }}
.stat:nth-child(1) {{ --accent:#23d3ee; --accent2:#4f8cff }}
.stat:nth-child(2) {{ --accent:#f8c76a; --accent2:#ff7a90 }}
.stat:nth-child(3) {{ --accent:#a78bfa; --accent2:#23d3ee }}
.stat:nth-child(4) {{ --accent:#28e0a6; --accent2:#23d3ee }}
.stat:nth-child(5) {{ --accent:#4f8cff; --accent2:#a78bfa }}
.stat.stat-alert {{ --accent:#f8c76a; --accent2:#ff7a90 }}
.stat.stat-ok {{ --accent:#28e0a6; --accent2:#23d3ee }}
.stat:hover {{ transform:translateY(-2px); border-color:color-mix(in srgb, var(--accent) 58%, rgba(148,163,184,.18)); box-shadow:0 20px 56px rgba(0,0,0,.30), 0 0 0 1px color-mix(in srgb, var(--accent) 12%, transparent), inset 0 1px 0 rgba(255,255,255,.07) }}
.stat span {{ order:1; color:color-mix(in srgb, var(--accent) 52%, #b7c4d8); font-size:11px; text-transform:uppercase; letter-spacing:.13em; font-weight:950; line-height:1.25 }}
.stat strong {{ order:2; display:block; color:#f8fbff; font-size:clamp(21px, 2.1vw, 31px); line-height:1.05; letter-spacing:-.055em; overflow-wrap:anywhere; text-shadow:0 0 24px color-mix(in srgb, var(--accent) 20%, transparent) }}
.mobile-apps {{ --quick-accent:#7dd3fc; --quick-accent2:#94a3b8; position:relative; margin:0 0 24px; padding:18px; border:1px solid color-mix(in srgb, var(--quick-accent) 24%, rgba(148,163,184,.16)); border-radius:24px; background:linear-gradient(145deg, color-mix(in srgb, var(--quick-accent) 8%, rgba(18,26,41,.94)), rgba(10,15,25,.91) 62%, color-mix(in srgb, var(--quick-accent2) 7%, rgba(8,12,20,.92))); box-shadow:0 16px 44px rgba(0,0,0,.20), inset 0 1px 0 rgba(255,255,255,.045); overflow:hidden; isolation:isolate }}
.mobile-apps:before {{ content:""; position:absolute; inset:0 0 auto 0; height:4px; background:linear-gradient(90deg, color-mix(in srgb, var(--quick-accent) 72%, #64748b), color-mix(in srgb, var(--quick-accent2) 72%, #475569)); opacity:.62 }}
.mobile-apps:after {{ content:""; position:absolute; width:170px; height:170px; right:-96px; top:-96px; border-radius:999px; background:radial-gradient(circle, color-mix(in srgb, var(--quick-accent) 12%, transparent), transparent 70%); opacity:.72; z-index:-1 }}
.mobile-apps h2 {{ color:#eef6ff; font-size:18px; line-height:1.05; letter-spacing:-.025em; margin:0 0 14px; text-shadow:0 0 18px color-mix(in srgb, var(--quick-accent) 10%, transparent) }}
.app-strip {{ display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:12px }}
.app-card {{ display:flex; gap:12px; align-items:center; border:1px solid rgba(35,211,238,.24); border-radius:22px; padding:16px; background:linear-gradient(135deg, rgba(35,211,238,.11), rgba(79,140,255,.07)); box-shadow:0 18px 54px rgba(0,0,0,.22) }}
.app-card b {{ display:block; font-size:17px; letter-spacing:-.02em; margin-bottom:3px }}
.app-card span {{ display:block; color:#b7c4d8; font-size:13px; line-height:1.35 }}
.app-card .app-card-icon {{ width:54px; height:54px; flex:0 0 54px; display:flex; align-items:center; justify-content:center; border-radius:18px; font-size:34px; line-height:1; color:#eaf4ff; background:rgba(255,255,255,.08); border:1px solid var(--line); text-align:center; transform:translateY(0) }}
.cron-menu {{ --cron-accent:#7dd3fc; --cron-accent2:#94a3b8; position:relative; margin:0 0 24px; border:1px solid color-mix(in srgb, var(--cron-accent) 24%, rgba(148,163,184,.16)); border-radius:24px; background:linear-gradient(145deg, color-mix(in srgb, var(--cron-accent) 8%, rgba(18,26,41,.94)), rgba(10,15,25,.91) 62%, color-mix(in srgb, var(--cron-accent2) 7%, rgba(8,12,20,.92))); box-shadow:0 16px 44px rgba(0,0,0,.20), inset 0 1px 0 rgba(255,255,255,.045); overflow:hidden; isolation:isolate }}
.cron-menu:before {{ content:""; position:absolute; inset:0 0 auto 0; height:4px; background:linear-gradient(90deg, color-mix(in srgb, var(--cron-accent) 72%, #64748b), color-mix(in srgb, var(--cron-accent2) 72%, #475569)); opacity:.62 }}
.cron-menu:after {{ content:""; position:absolute; width:170px; height:170px; right:-96px; top:-96px; border-radius:999px; background:radial-gradient(circle, color-mix(in srgb, var(--cron-accent) 12%, transparent), transparent 70%); opacity:.72; z-index:-1 }}
.cron-menu summary {{ min-height:68px; list-style:none; cursor:pointer; display:flex; align-items:center; justify-content:space-between; gap:14px; padding:17px 18px 16px; touch-action:manipulation }}
.cron-menu summary::-webkit-details-marker {{ display:none }}
.cron-summary-main {{ display:flex; align-items:center; gap:12px; min-width:0 }}
.cron-summary-main b {{ display:block; color:#eef6ff; font-size:18px; line-height:1.05; letter-spacing:-.025em; text-shadow:0 0 18px color-mix(in srgb, var(--cron-accent) 10%, transparent) }}
.cron-summary-main small {{ display:block; margin-top:5px; color:color-mix(in srgb, var(--cron-accent) 36%, #94a3b8); font-size:11px; font-weight:900; letter-spacing:.1em; text-transform:uppercase }}
.cron-dot {{ width:12px; height:12px; border-radius:999px; background:color-mix(in srgb, var(--green) 70%, #94a3b8); box-shadow:0 0 18px rgba(40,224,166,.38); flex:0 0 auto }}
.cron-chevron {{ color:#c8d6ea; font-size:24px; line-height:1; transition:transform .16s ease, color .16s ease }}
.cron-menu:hover .cron-chevron {{ color:#e8f2ff }}
.cron-menu[open] .cron-chevron {{ transform:rotate(180deg) }}
.cron-panel {{ display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:12px; padding:0 12px 14px }}
.cron-item {{ --job-accent:#7dd3fc; position:relative; overflow:hidden; border:1px solid color-mix(in srgb, var(--job-accent) 20%, rgba(148,163,184,.14)); border-radius:18px; background:linear-gradient(145deg, color-mix(in srgb, var(--job-accent) 7%, rgba(18,26,41,.88)), rgba(10,16,27,.82)); padding:14px; display:grid; gap:10px; box-shadow:0 12px 32px rgba(0,0,0,.16), inset 0 1px 0 rgba(255,255,255,.035) }}
.cron-item:before {{ content:""; position:absolute; inset:0 0 auto 0; height:3px; background:linear-gradient(90deg, color-mix(in srgb, var(--job-accent) 58%, #64748b), rgba(148,163,184,.18)); opacity:.58 }}
.cron-item:nth-child(2n) {{ --job-accent:#a78bfa }}
.cron-item:nth-child(3n) {{ --job-accent:#28e0a6 }}
.cron-item:nth-child(4n) {{ --job-accent:#f8c76a }}
.cron-item.disabled {{ --job-accent:#94a3b8; opacity:.72; background:linear-gradient(145deg, rgba(18,26,41,.62), rgba(10,16,27,.58)) }}
.cron-item-top {{ display:flex; align-items:flex-start; justify-content:space-between; gap:10px }}
.cron-item-top strong {{ color:#edf5ff; font-size:15px; line-height:1.25; letter-spacing:-.01em }}
.cron-status {{ flex:0 0 auto; font-size:10px; font-weight:950; text-transform:uppercase; letter-spacing:.09em; border-radius:999px; padding:5px 8px; border:1px solid rgba(40,224,166,.20); color:#a8f1dc; background:rgba(40,224,166,.065) }}
.cron-status.disabled {{ color:#e8c989; background:rgba(248,199,106,.055); border-color:rgba(248,199,106,.18) }}
.cron-next {{ display:grid; gap:4px; border-radius:14px; padding:10px 12px; background:color-mix(in srgb, var(--job-accent) 7%, rgba(255,255,255,.025)); border:1px solid color-mix(in srgb, var(--job-accent) 15%, rgba(148,163,184,.12)) }}
.cron-next span,.cron-section-label {{ color:color-mix(in srgb, var(--job-accent) 32%, #94a3b8); font-size:10px; text-transform:uppercase; letter-spacing:.11em; font-weight:950 }}
.cron-next b {{ color:#f4f8ff; font-size:15px; line-height:1.12 }}
.cron-meta {{ display:flex; flex-wrap:wrap; gap:7px; color:#aebbd0; font-size:11px }}
.cron-meta span {{ border:1px solid color-mix(in srgb, var(--job-accent) 12%, rgba(148,163,184,.13)); background:rgba(255,255,255,.022); border-radius:999px; padding:5px 7px }}
.cron-disabled {{ display:grid; grid-column:1/-1; gap:10px; margin-top:2px; padding-top:12px; border-top:1px dashed rgba(148,163,184,.18) }}
.cron-empty {{ color:var(--muted); padding:16px; text-align:center }}
.grid {{ display:grid; grid-template-columns:repeat(3, minmax(0, 1fr)); gap:16px }}
.card {{ background:linear-gradient(180deg, rgba(18,26,41,.95), rgba(11,16,26,.95)); border:1px solid var(--line); border-radius:var(--radius); padding:20px; min-height:255px; display:flex; flex-direction:column; box-shadow:0 18px 48px rgba(0,0,0,.2); transition:transform .16s ease, border-color .16s ease }}
.card:hover {{ transform:translateY(-2px); border-color:rgba(35,211,238,.45) }}
.card-top {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:18px }}
.icon {{ font-size:24px; width:42px; height:42px; border-radius:14px; display:grid; place-items:center; background:rgba(255,255,255,.06); border:1px solid var(--line) }}
.badge {{ color:#89f7d1; background:rgba(40,224,166,.09); border:1px solid rgba(40,224,166,.24); padding:6px 10px; border-radius:999px; font-size:12px; font-weight:800 }}
.card h2 {{ font-size:20px; line-height:1.22; letter-spacing:-.025em; margin:0 0 10px }}
.path {{ color:var(--muted); font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; line-height:1.45; word-break:break-word; margin:0 0 16px }}
.meta {{ display:flex; flex-wrap:wrap; gap:8px; margin-top:auto; color:#aebbd0; font-size:12px }}
.meta span {{ border:1px solid var(--line); background:rgba(255,255,255,.035); border-radius:999px; padding:6px 8px }}
.actions {{ display:flex; gap:10px; margin-top:16px }}
.primary,.secondary {{ border-radius:13px; padding:10px 12px; font-weight:800; font-size:13px; text-align:center }}
.primary {{ flex:1; background:linear-gradient(135deg, var(--blue), var(--cyan)); color:white }}
.secondary {{ border:1px solid var(--line); color:#c9d6e8; background:rgba(255,255,255,.04) }}
.footer {{ color:var(--muted); font-size:12px; margin-top:26px; text-align:center }}
@media (max-width:960px) {{ .grid {{ grid-template-columns:repeat(2, minmax(0,1fr)) }} .stats {{ grid-template-columns:repeat(2, minmax(0,1fr)) }} }}
@media (max-width:640px) {{ .shell {{ width:min(1280px, calc(100% - 20px)); padding:14px 0 36px }} .grid,.stats,.app-strip,.cron-panel {{ grid-template-columns:1fr }} .hero {{ padding:16px 18px; border-radius:22px }} .hero-row {{ gap:8px }} h1 {{ font-size:clamp(27px, 8vw, 36px); margin:10px 0 0 }} .hero-refresh {{ width:52px; height:52px; min-width:52px; min-height:52px; border-radius:20px }} .hero-refresh:before {{ border-radius:18px }} .hero-refresh-icon {{ font-size:29px }} .cron-menu,.mobile-apps {{ border-radius:20px; margin-bottom:18px }} .mobile-apps {{ padding:15px }} .cron-menu summary {{ padding:15px; min-height:62px }} .cron-panel {{ padding:0 8px 10px }} .cron-item {{ padding:12px; border-radius:16px }} .cron-item-top {{ flex-direction:column; align-items:flex-start }} .cron-next b {{ font-size:14px }} .cron-meta {{ flex-direction:column; align-items:flex-start }} .actions {{ flex-direction:column }} }}
</style>
</head>
<body>
<div class="shell">
  <section class="hero">
    <div class="hero-row">
      <div class="kicker">● Private LAN Portal</div>
      <button class="hero-refresh" type="button" aria-label="Refresh Mac Studio LAN Portal and metrics" title="Refresh Mac Studio LAN Portal and metrics" aria-busy="false">
        <span class="hero-refresh-icon" aria-hidden="true">↻</span>
      </button>
    </div>
    <h1>Mac Studio LAN Portal</h1>
  </section>
  <section class="stats">
    <a class="stat{system_uptime_class}" href="/metrics/system-uptime" title="{html.escape(system_uptime_detail)}"><span>System uptime</span><strong>{html.escape(system_uptime_value)}</strong></a>
    <a class="stat{updates_class}" href="/admin" title="{html.escape(updates_detail)}"><span>Updates</span><strong>{html.escape(updates_value)}</strong></a>
    <a class="stat{hermes_backup_class}" href="/metrics/hermes-backups" title="{html.escape(hermes_backup_detail)}"><span>Last Hermes backup</span><strong>{html.escape(hermes_backup_value)}</strong></a>
    <a class="stat{local_disk_class}" href="/metrics/local-disk" title="{html.escape(local_disk_detail)}"><span>Local disk free</span><strong>{human_size(local_free_space)}</strong></a>
    <a class="stat{portal_update_class}" href="/metrics/portal-update" title="{html.escape(portal_update_detail)}"><span>Latest Portal update</span><strong>{html.escape(portal_update_value)}</strong></a>
  </section>
  {cyber_portal_html}
  {mobile_apps_html}
  <div class="footer">Generated live by report_portal.py · metrics refresh from configured local checks · dashboard links are explicit only</div>
</div>
<script>
const DISK_METRIC_REFRESH_MS = 30 * 60 * 1000;
const refreshButton = document.querySelector('.hero-refresh');
function startMetricRefresh(paramName = 'refresh') {{
  const url = new URL(window.location.href);
  url.searchParams.set(paramName, Date.now().toString());
  if (refreshButton) {{
    refreshButton.classList.add('refreshing');
    refreshButton.setAttribute('aria-busy', 'true');
    refreshButton.setAttribute('aria-label', 'Refreshing Mac Studio LAN Portal metrics');
    refreshButton.setAttribute('title', 'Refreshing Mac Studio LAN Portal metrics');
    refreshButton.disabled = true;
  }}
  window.requestAnimationFrame(() => window.setTimeout(() => window.location.replace(url.toString()), 90));
}}
refreshButton?.addEventListener('click', () => startMetricRefresh('refresh'));
window.setTimeout(() => {{
  startMetricRefresh('disk_metric_refresh');
}}, DISK_METRIC_REFRESH_MS);
</script>
</body>
</html>'''
    return page.encode("utf-8")


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
    try:
        record = json.loads(enrichment_json or "{}") if isinstance(enrichment_json, str) else (enrichment_json or {})
    except Exception:
        record = {}
    external_intel = record.get("external_intel") if isinstance(record, dict) else {}
    if not isinstance(external_intel, dict):
        return {
            "enrichment_status_key": "none",
            "enrichment_status_label": "None",
            "enrichment_status_detail": "No public enrichment data recorded for this alert group",
            "enrichment_record_count": 0,
            "enrichment_skip_count": 0,
            "enrichment_error_count": 0,
        }

    records = external_intel.get("records") if isinstance(external_intel.get("records"), list) else []
    skipped = external_intel.get("skipped") if isinstance(external_intel.get("skipped"), list) else []
    errors = external_intel.get("errors") if isinstance(external_intel.get("errors"), list) else []
    indicators = external_intel.get("indicators") if isinstance(external_intel.get("indicators"), dict) else {}
    indicator_count = sum(
        len(indicators.get(key) or [])
        for key in ("public_ips", "domains", "urls", "hashes", "cves")
        if isinstance(indicators.get(key), list)
    )

    if records:
        detail = f"{len(records)} enrichment record(s), {len(skipped)} skipped source(s), {len(errors)} error(s)"
        key, label = "enriched", "Enriched"
    elif errors:
        detail = f"{len(errors)} enrichment error(s), {len(skipped)} skipped source(s)"
        key, label = "error", "Error"
    elif skipped:
        detail = f"Indicators found, but {len(skipped)} source(s) skipped or unavailable"
        key, label = "checked", "Checked"
    elif indicator_count:
        detail = f"{indicator_count} public indicator(s) found with no completed enrichment records yet"
        key, label = "pending", "Pending"
    else:
        detail = "No public indicators were recorded for enrichment"
        key, label = "none", "None"
    return {
        "enrichment_status_key": key,
        "enrichment_status_label": label,
        "enrichment_status_detail": detail,
        "enrichment_record_count": len(records),
        "enrichment_skip_count": len(skipped),
        "enrichment_error_count": len(errors),
    }


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
    """Return true only for parser artifacts that actually include captures."""
    pcap_files = record.get("pcap_files") if isinstance(record.get("pcap_files"), list) else []
    if not pcap_files:
        return False
    zeek = record.get("zeek") if isinstance(record.get("zeek"), dict) else {}
    tshark = record.get("tshark") if isinstance(record.get("tshark"), dict) else {}
    return bool(zeek.get("available") or tshark.get("available"))


def read_artifact_cache(name: str, path: Path) -> object | None:
    return SOC_ALERT_ARTIFACT_CACHE.get(name, path)


def write_artifact_cache(name: str, path: Path, value: object) -> object:
    return SOC_ALERT_ARTIFACT_CACHE.put(name, path, value)


def soc_alert_pcap_analysis_index() -> dict[str, object]:
    """Index parsed Zeek/TShark artifacts once per API response."""
    def build_index() -> dict[str, object]:
        index: dict[str, object] = {
            "request_ids": set(),
            "alert_ids": set(),
            "group_ids": set(),
            "size_by_alert_id": {},
            "size_by_group_id": {},
        }
        seen_sizes: dict[str, set[tuple[str, str]]] = {
            "size_by_alert_id": set(),
            "size_by_group_id": set(),
        }
        if not SOC_ALERT_PCAP_ANALYSIS_DIR.exists():
            return index
        for path in SOC_ALERT_PCAP_ANALYSIS_DIR.glob("*-pcap-analysis.json"):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(record, dict) or not soc_alert_has_parsed_pcap(record):
                continue
            request = record.get("request") if isinstance(record.get("request"), dict) else {}
            for key, bucket in (("request_id", "request_ids"), ("alert_id", "alert_ids"), ("group_id", "group_ids")):
                value = str(request.get(key) or "").strip()
                if value:
                    index[bucket].add(value)
            pcap_files = record.get("pcap_files") if isinstance(record.get("pcap_files"), list) else []
            request_id = str(request.get("request_id") or "").strip()
            for position, item in enumerate(pcap_files):
                if not isinstance(item, dict):
                    continue
                try:
                    capture_bytes = max(0, int(item.get("size_bytes") or 0))
                except (TypeError, ValueError):
                    # A malformed historical artifact must not break the alert
                    # list API; valid files in the same analysis still count.
                    continue
                if capture_bytes <= 0:
                    continue
                identity = str(
                    item.get("sha256")
                    or item.get("artifact_sha256")
                    or item.get("path")
                    or item.get("file")
                    or f"{request_id}:{position}"
                ).strip()
                for request_key, size_key in (("alert_id", "size_by_alert_id"), ("group_id", "size_by_group_id")):
                    value = str(request.get(request_key) or "").strip()
                    artifact_key = (value, identity)
                    if not value or artifact_key in seen_sizes[size_key]:
                        continue
                    seen_sizes[size_key].add(artifact_key)
                    sizes = index[size_key]
                    sizes[value] = int(sizes.get(value, 0)) + capture_bytes
        return index

    return SOC_ALERT_ARTIFACT_CACHE.get_or_compute(
        "pcap-analysis-index", SOC_ALERT_PCAP_ANALYSIS_DIR, build_index
    )


def soc_alert_pcap_request_statuses(conn: sqlite3.Connection, rows: list[sqlite3.Row | dict]) -> dict[str, dict]:
    """Return newest broker status keyed by group id and alert id for page rows."""
    if not sqlite_table_exists(conn, "pcap_requests"):
        return {}
    def row_value(row: sqlite3.Row | dict, key: str, default: str = "") -> str:
        if isinstance(row, dict):
            return str(row.get(key, default) or "")
        return str(row[key] or "") if key in row.keys() else str(default or "")

    group_ids = {
        (row_value(row, "group_id") or soc_alert_group_id(row_value(row, "group_key"))).strip()
        for row in rows
        if row_value(row, "group_id") or row_value(row, "group_key")
    }
    alert_ids = {
        row_value(row, "alert_id").strip()
        for row in rows
        if row_value(row, "alert_id").strip()
    }
    terms = sorted(group_ids | alert_ids)
    if not terms:
        return {}
    placeholders = ",".join("?" for _ in terms)
    try:
        found = conn.execute(
            f"""
            SELECT request_id, alert_id, group_id, status, error, request_json, updated_at, completed_at
            FROM pcap_requests
            WHERE group_id IN ({placeholders}) OR alert_id IN ({placeholders}) OR request_id IN ({placeholders})
            ORDER BY COALESCE(completed_at, updated_at, created_at) DESC
            """,
            [*terms, *terms, *terms],
        ).fetchall()
    except sqlite3.Error:
        return {}
    statuses: dict[str, dict] = {}
    for item in found:
        record = {
            "request_id": str(item["request_id"] or "").strip(),
            "status": str(item["status"] or "").strip().lower(),
            "error": str(item["error"] or "").strip(),
            "updated_at": str(item["completed_at"] or item["updated_at"] or "").strip(),
            "used_capture_file": False,
        }
        try:
            request_json = json.loads(str(item["request_json"] or "{}"))
            record["used_capture_file"] = bool(str(request_json.get("capture_file") or "").strip())
        except (TypeError, ValueError):
            record["used_capture_file"] = False
        for key in ("group_id", "alert_id", "request_id"):
            value = str(item[key] or "").strip()
            if value and value not in statuses:
                statuses[value] = record
    return statuses


def soc_alert_pcap_status(group_id: str, alert_id: str, analysis_index: dict[str, object], request_statuses: dict[str, dict]) -> dict:
    """Return the compact PCAP table status for one grouped alert."""
    group_id = str(group_id or "").strip()
    alert_id = str(alert_id or "").strip()
    if group_id in analysis_index.get("group_ids", set()) or alert_id in analysis_index.get("alert_ids", set()):
        return {
            "pcap_status_key": "analyzed",
            "pcap_status_label": "Analyzed",
            "pcap_status_detail": "Parsed Zeek/TShark PCAP analysis is available for this detection group",
        }
    request_record = request_statuses.get(group_id) or request_statuses.get(alert_id) or {}
    request_status = str(request_record.get("status") or "").strip().lower() if isinstance(request_record, dict) else str(request_record or "").strip().lower()
    if request_status in {"pending", "claimed", "fulfilled"}:
        return {
            "pcap_status_key": "queued",
            "pcap_status_label": "Queued" if request_status in {"pending", "claimed"} else "Parsing",
            "pcap_status_detail": f"PCAP request is {request_status}; parsed analysis is not available yet",
        }
    if request_status == "failed":
        error = str(request_record.get("error") or "").strip() if isinstance(request_record, dict) else ""
        if "no matching packets" in error.lower():
            if isinstance(request_record, dict) and not request_record.get("used_capture_file"):
                return {
                    "pcap_status_key": "error",
                    "pcap_status_label": "Retry",
                    "pcap_status_detail": "Older PCAP request did not include the Security Onion capture file hint; retry the request before treating this as no packets",
                }
            return {
                "pcap_status_key": "no-packets",
                "pcap_status_label": "No Packets",
                "pcap_status_detail": "Security Onion found no matching packets for the requested flow/window",
            }
        return {
            "pcap_status_key": "error",
            "pcap_status_label": "Failed",
            "pcap_status_detail": (error[:180] if error else "PCAP request failed before parsed analysis was produced"),
        }
    return {
        "pcap_status_key": "none",
        "pcap_status_label": "None",
        "pcap_status_detail": "No parsed PCAP analysis is available for this detection group",
    }


def soc_alert_pcap_analysis_record(group_id: str) -> dict | None:
    """Return newest parsed PCAP evidence for a grouped alert detail fragment."""
    group_id = str(group_id or "").strip()
    if not group_id or not SOC_ALERT_PCAP_ANALYSIS_DIR.exists():
        return None
    matches: list[tuple[float, dict]] = []
    for path in SOC_ALERT_PCAP_ANALYSIS_DIR.glob("*-pcap-analysis.json"):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(record, dict) or not soc_alert_has_parsed_pcap(record):
            continue
        request = record.get("request") if isinstance(record.get("request"), dict) else {}
        if str(request.get("group_id") or "").strip() != group_id:
            continue
        record["_analysis_path"] = str(path)
        matches.append((path.stat().st_mtime, record))
    if not matches:
        return None
    return sorted(matches, key=lambda item: item[0])[-1][1]


def soc_alert_pcap_summary_html(record: dict) -> str:
    """Render bounded, escaped parsed packet evidence for lazy detail loading."""
    def esc(value: object) -> str:
        return html.escape("n/a" if value is None else str(value))

    def compact_json(value: object, limit: int = 2400) -> str:
        text = json.dumps(value, indent=2, sort_keys=True) if not isinstance(value, str) else value
        text = text.strip() or "n/a"
        if len(text) > limit:
            text = text[:limit].rstrip() + "\n... truncated ..."
        return html.escape(text)

    request = record.get("request") if isinstance(record.get("request"), dict) else {}
    zeek = record.get("zeek") if isinstance(record.get("zeek"), dict) else {}
    tshark = record.get("tshark") if isinstance(record.get("tshark"), dict) else {}
    pcap_files = record.get("pcap_files") if isinstance(record.get("pcap_files"), list) else []
    analysis_name = Path(str(record.get("_analysis_path") or "")).name or "n/a"
    rows = [
        ("Status", "Parsed"),
        ("Request ID", request.get("request_id")),
        ("Generated", record.get("generated_at")),
        ("PCAP files parsed", len(pcap_files)),
        ("Analysis artifact", analysis_name),
    ]
    summary_rows = "\n".join(
        f"<tr><th>{esc(label)}</th><td>{esc(value)}</td></tr>"
        for label, value in rows
    )
    parts = [
        '<section class="detail-section parsed-pcap-evidence">',
        "<h3>Parsed PCAP Evidence</h3>",
        "<p>Current Zeek/TShark packet evidence for this grouped detection. "
        "This section is generated from parsed summaries; raw packet payloads are not displayed.</p>",
        f'<table class="detail-kv-table"><tbody>{summary_rows}</tbody></table>',
        "<h4>Zeek Summary</h4>",
    ]
    if zeek.get("available"):
        record_counts = zeek.get("record_counts") if isinstance(zeek.get("record_counts"), dict) else {}
        parts.append(f"<p><strong>Record counts:</strong> <code>{esc(json.dumps(record_counts, sort_keys=True))}</code></p>")
        for title, key in (
            ("Top Connections", "top_connections"),
            ("DNS Queries", "dns_queries"),
            ("TLS SNI", "tls_sni"),
            ("HTTP Hosts", "http_hosts"),
            ("Notices", "notices"),
            ("Weird Activity", "weird"),
        ):
            values = zeek.get(key) if isinstance(zeek.get(key), list) else []
            if values:
                parts.extend([f"<h5>{esc(title)}</h5>", f"<pre><code>{compact_json(values[:10])}</code></pre>"])
    else:
        parts.append(f"<p>Zeek unavailable: {esc(zeek.get('reason'))}</p>")
    parts.append("<h4>TShark Corroboration</h4>")
    if tshark.get("available"):
        samples = tshark.get("samples") if isinstance(tshark.get("samples"), list) else []
        if not samples:
            parts.append("<p>No bounded TShark samples were produced.</p>")
        for sample in samples[:2]:
            if not isinstance(sample, dict):
                continue
            parts.extend(
                [
                    "<h5>Protocol hierarchy</h5>",
                    f"<pre><code>{compact_json(sample.get('protocol_hierarchy'), 1800)}</code></pre>",
                    "<h5>Conversations</h5>",
                    f"<pre><code>{compact_json(sample.get('conversations'), 1800)}</code></pre>",
                ]
            )
    else:
        parts.append(f"<p>TShark unavailable: {esc(tshark.get('reason'))}</p>")
    parts.append("</section>")
    return "\n".join(parts)


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
        reviewer_logs.append({
            **{
                key: parent.get(key)
                for key in (
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
                if key in parent
            },
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
        })
    return reviewer_logs


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


def llm_analysis_logs_response(query: dict[str, list[str]]) -> dict:
    requested_page = llm_analysis_log_page((query.get("page") or ["1"])[0])
    limit = llm_analysis_log_limit((query.get("limit") or ["25"])[0])
    primary_total, _, _ = SOC_ALERT_LLM_ANALYSIS_LOG_INDEX.page(page=1, limit=1)
    reviewer_logs = read_llm_second_opinion_logs([])
    total = primary_total + len(reviewer_logs)
    total_pages = max(1, math.ceil(total / limit)) if total else 1
    page = min(requested_page, total_pages)
    # At most `page * limit` primary rows can appear before the requested
    # combined page. Reading only that prefix keeps the common first-page poll
    # proportional to the page size instead of reparsing the entire JSONL log.
    primary_total, _, primary_logs = SOC_ALERT_LLM_ANALYSIS_LOG_INDEX.page(
        page=1,
        limit=page * limit,
    )
    if primary_logs:
        parents = {
            str(record.get("log_id") or ""): record
            for record in primary_logs
            if record.get("log_id")
        }
        for reviewer in reviewer_logs:
            parent = parents.get(str(reviewer.get("parent_log_id") or ""))
            if parent:
                reviewer["alert"] = parent.get("alert") or reviewer.get("alert")
    combined = [*primary_logs, *reviewer_logs]
    combined.sort(
        key=lambda record: (
            _llm_log_sort_timestamp(record),
            str(record.get("log_id") or ""),
        ),
        reverse=True,
    )
    start = (page - 1) * limit
    logs = combined[start:start + limit]
    return {
        "ok": True,
        "page": page,
        "limit": limit,
        "total": total,
        "primary_total": primary_total,
        "second_opinion_total": len(reviewer_logs),
        "history_truncated": len(reviewer_logs) >= LLM_ANALYSIS_COMBINED_HISTORY_LIMIT,
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


def soc_alert_latest_prompt_mtime(alert_id: str) -> float:
    if not alert_id or not SOC_ALERT_AI_PROMPT_DIR.exists():
        return 0
    newest = 0.0
    for path in SOC_ALERT_AI_PROMPT_DIR.glob("*-ai-prompt.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
        if str(alert.get("alert_id") or data.get("alert_id") or "").strip() == alert_id:
            newest = max(newest, path.stat().st_mtime)
    return newest


def soc_alert_latest_analysis_mtime(alert_id: str) -> float:
    if not alert_id or not SOC_ALERT_AI_ANALYSIS_DIR.exists():
        return 0
    newest = 0.0
    for path in SOC_ALERT_AI_ANALYSIS_DIR.glob("*-local-ai-analysis.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if str(data.get("alert_id") or "").strip() == alert_id:
            newest = max(newest, path.stat().st_mtime)
    return newest


def soc_alert_ai_artifact_index() -> dict[str, object]:
    """Index AI prompt/analysis artifact mtimes once for one API response."""
    cache_path = SOC_ALERT_AI_ANALYSIS_DIR.parent
    def build_index() -> dict[str, object]:
        prompt_mtime_by_alert: dict[str, float] = {}
        analysis_mtime_by_alert: dict[str, float] = {}
        detection_outcome_by_alert: dict[str, str] = {}
        prompt_dir_matches_analysis = (
            SOC_ALERT_AI_PROMPT_DIR.exists()
            and SOC_ALERT_AI_ANALYSIS_DIR.exists()
            and SOC_ALERT_AI_PROMPT_DIR.parent == SOC_ALERT_AI_ANALYSIS_DIR.parent
        )
        if prompt_dir_matches_analysis:
            for path in SOC_ALERT_AI_PROMPT_DIR.glob("*-ai-prompt.json"):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    continue
                alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
                alert_id = str(alert.get("alert_id") or data.get("alert_id") or "").strip()
                if alert_id:
                    prompt_mtime_by_alert[alert_id] = max(prompt_mtime_by_alert.get(alert_id, 0.0), path.stat().st_mtime)
        if SOC_ALERT_AI_ANALYSIS_DIR.exists():
            for path in SOC_ALERT_AI_ANALYSIS_DIR.glob("*-local-ai-analysis.json"):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    continue
                alert_id = str(data.get("alert_id") or "").strip()
                if alert_id:
                    artifact_mtime = path.stat().st_mtime
                    if artifact_mtime >= analysis_mtime_by_alert.get(alert_id, 0.0):
                        analysis_mtime_by_alert[alert_id] = artifact_mtime
                        response = data.get("response") if isinstance(data.get("response"), dict) else {}
                        outcome = str(response.get("detection_outcome") or data.get("detection_outcome") or "").strip()
                        if outcome:
                            detection_outcome_by_alert[alert_id] = outcome
        return {
            "prompt_mtime_by_alert": prompt_mtime_by_alert,
            "analysis_mtime_by_alert": analysis_mtime_by_alert,
            "detection_outcome_by_alert": detection_outcome_by_alert,
        }

    return SOC_ALERT_ARTIFACT_CACHE.get_or_compute("ai-artifact-index", cache_path, build_index)


def soc_alert_page_ai_artifact_context(rows: list[sqlite3.Row | dict]) -> dict[str, object]:
    """Return page-scoped AI artifact state without per-row filesystem scans."""
    artifact_index = soc_alert_ai_artifact_index()
    analysis_mtime_by_alert = artifact_index["analysis_mtime_by_alert"]
    detection_outcome_by_alert = artifact_index["detection_outcome_by_alert"]
    analysis_group_ids: set[str] = set()
    detection_outcome_by_group_id: dict[str, str] = {}
    outcome_mtime_by_group_id: dict[str, float] = {}
    group_keys: list[str] = []

    def consider_outcome(group_id: str, alert_id: str) -> None:
        outcome = str(detection_outcome_by_alert.get(alert_id) or "").strip()
        mtime = float(analysis_mtime_by_alert.get(alert_id, 0.0) or 0.0)
        if outcome and mtime >= outcome_mtime_by_group_id.get(group_id, 0.0):
            detection_outcome_by_group_id[group_id] = outcome
            outcome_mtime_by_group_id[group_id] = mtime

    for row in rows:
        if isinstance(row, dict):
            group_key = str(row.get("group_key") or "").strip()
            alert_id = str(row.get("alert_id") or row.get("representative_alert_id") or "").strip()
        else:
            group_key = str(row["group_key"] or "").strip() if "group_key" in row.keys() else ""
            alert_id = str(row["alert_id"] or row["representative_alert_id"] or "").strip() if "alert_id" in row.keys() else ""
        if group_key:
            group_keys.append(group_key)
            group_id = soc_alert_group_id(group_key)
            if alert_id in analysis_mtime_by_alert:
                analysis_group_ids.add(group_id)
            consider_outcome(group_id, alert_id)
    group_keys = sorted(set(group_keys))
    if group_keys and analysis_mtime_by_alert:
        placeholders = ",".join("?" for _ in group_keys)
        try:
            with soc_alert_db_connect() as conn:
                found = conn.execute(
                    f"""
                    SELECT {soc_alert_group_key_sql()} AS group_key, alert_id
                    FROM alerts
                    WHERE {soc_alert_group_key_sql()} IN ({placeholders})
                    """,
                    group_keys,
                ).fetchall()
            for item in found:
                if str(item["alert_id"] or "").strip() in analysis_mtime_by_alert:
                    group_key = str(item["group_key"] or "").strip()
                    if group_key:
                        group_id = soc_alert_group_id(group_key)
                        alert_id = str(item["alert_id"] or "").strip()
                        analysis_group_ids.add(group_id)
                        consider_outcome(group_id, alert_id)
        except Exception:
            pass
    return {
        **artifact_index,
        "analysis_group_ids": analysis_group_ids,
        "detection_outcome_by_group_id": detection_outcome_by_group_id,
    }


def soc_alert_group_has_analysis_artifact(row: sqlite3.Row) -> bool:
    """Return true when any current member of this dashboard group has AI output."""
    if not SOC_ALERT_AI_ANALYSIS_DIR.exists():
        return False
    group_key = row["group_key"] if "group_key" in row.keys() else ""
    representative = str(row["alert_id"] or "") if "alert_id" in row.keys() else ""
    member_ids: set[str] = {representative} if representative else set()
    if group_key:
        try:
            with soc_alert_db_connect() as conn:
                member_ids.update(
                    str(item["alert_id"] or "").strip()
                    for item in conn.execute(
                        f"""
                        SELECT alert_id
                        FROM alerts
                        WHERE {soc_alert_group_key_sql()} = ?
                        """,
                        [group_key],
                    )
                    if str(item["alert_id"] or "").strip()
                )
        except Exception:
            pass
    return any(soc_alert_latest_analysis_mtime(alert_id) > 0 for alert_id in member_ids)


def soc_alert_severity_meets_analysis_threshold(
    severity: object,
    threshold: object,
) -> bool:
    normalized_severity = str(severity or "informational").strip().lower()
    normalized_threshold = str(threshold or "informational").strip().lower()
    if normalized_severity == "info":
        normalized_severity = "informational"
    if normalized_threshold == "info":
        normalized_threshold = "informational"
    if normalized_threshold == "disabled":
        return False
    if normalized_threshold not in SOC_ANALYSIS_SEVERITY_ORDER:
        normalized_threshold = "informational"
    if normalized_severity not in SOC_ANALYSIS_SEVERITY_ORDER:
        return False
    return (
        SOC_ANALYSIS_SEVERITY_ORDER.index(normalized_severity)
        >= SOC_ANALYSIS_SEVERITY_ORDER.index(normalized_threshold)
    )


def soc_alert_group_ai_status(
    row: sqlite3.Row,
    group_id: str,
    ai_reports: dict | None = None,
    ai_artifacts: dict[str, object] | None = None,
    analysis_min_severity: str = "informational",
) -> dict:
    alert_id = str(row["alert_id"] or "") if "alert_id" in row.keys() else ""
    prompt_mtime_by_alert = ai_artifacts.get("prompt_mtime_by_alert", {}) if isinstance(ai_artifacts, dict) else {}
    analysis_mtime_by_alert = ai_artifacts.get("analysis_mtime_by_alert", {}) if isinstance(ai_artifacts, dict) else {}
    analysis_group_ids = ai_artifacts.get("analysis_group_ids", set()) if isinstance(ai_artifacts, dict) else set()
    prompt_mtime = float(prompt_mtime_by_alert.get(alert_id, 0.0)) if isinstance(prompt_mtime_by_alert, dict) else 0.0
    analysis_mtime = float(analysis_mtime_by_alert.get(alert_id, 0.0)) if isinstance(analysis_mtime_by_alert, dict) else 0.0
    if alert_id and not ai_artifacts:
        prompt_mtime = soc_alert_latest_prompt_mtime(alert_id)
        analysis_mtime = soc_alert_latest_analysis_mtime(alert_id)
    if alert_id and prompt_mtime > analysis_mtime:
        return {
            "ai_status_key": "queued",
            "ai_status_label": "Queued",
            "ai_status_detail": "Manual SOC Analyst reanalysis prompt package is waiting for the local AI worker",
        }

    reports = ai_reports if isinstance(ai_reports, dict) else soc_alert_static_ai_reports()
    status = reports.get(group_id)
    has_artifact = (
        group_id in analysis_group_ids
        if ai_artifacts
        else soc_alert_group_has_analysis_artifact(row)
    )
    triage_level = (
        row["triage_level"]
        if "triage_level" in row.keys()
        else "informational"
    )
    normalized_triage_level = str(triage_level or "").strip().lower()
    if normalized_triage_level == "info":
        normalized_triage_level = "informational"
    if (
        not has_artifact
        and normalized_triage_level not in SOC_ANALYSIS_SEVERITY_ORDER
    ):
        return {
            "ai_status_key": "not-queued",
            "ai_status_label": "Skipped",
            "ai_status_detail": (
                f"Unrecognized severity {normalized_triage_level or 'blank'} "
                "is not eligible for automatic AI analysis"
            ),
        }
    if (
        not has_artifact
        and not soc_alert_severity_meets_analysis_threshold(
            triage_level,
            analysis_min_severity,
        )
    ):
        threshold_label = str(analysis_min_severity or "informational").strip().title()
        return {
            "ai_status_key": "not-queued",
            "ai_status_label": "Skipped",
            "ai_status_detail": (
                f"Below configured {threshold_label} automatic AI-analysis minimum"
            ),
        }
    if isinstance(status, dict):
        key = str(status.get("ai_status_key") or "queued")
        filter_status = str(row["filter_status"] or "accepted").strip().lower() if "filter_status" in row.keys() else "accepted"
        if key in {"analyzed", "analyzing"} and not has_artifact:
            return {
                "ai_status_key": "queued",
                "ai_status_label": "Queued",
                "ai_status_detail": "The previous AI status was stale; no AI analysis artifact exists for this group",
            }
        if key in {"not-queued", "skipped"} and filter_status in SOC_ALERT_AI_ELIGIBLE_FILTER_STATUSES and not has_artifact:
            return {
                "ai_status_key": "queued",
                "ai_status_label": "Queued",
                "ai_status_detail": "No AI analysis artifact exists for this eligible group; queued for the scheduled local AI analysis worker",
            }
        return {
            "ai_status_key": key,
            "ai_status_label": str(status.get("ai_status_label") or "Queued"),
            "ai_status_detail": str(status.get("ai_status_detail") or ""),
        }

    if alert_id and alert_id.startswith(SOC_ALERT_TEST_PREFIXES):
        return {
            "ai_status_key": "not-queued",
            "ai_status_label": "Skipped",
            "ai_status_detail": "Test/validation alert is intentionally excluded from automatic local AI analysis",
        }

    filter_status = str(row["filter_status"] or "accepted").strip().lower() if "filter_status" in row.keys() else "accepted"
    if filter_status not in SOC_ALERT_AI_ELIGIBLE_FILTER_STATUSES:
        return {
            "ai_status_key": "not-queued",
            "ai_status_label": "Skipped",
            "ai_status_detail": f"Filter status {filter_status or 'blank'} is not eligible for automatic local AI analysis",
        }

    return {
        "ai_status_key": "queued",
        "ai_status_label": "Queued",
        "ai_status_detail": "Queued for the scheduled local AI analysis worker",
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


def soc_alert_detection_outcome_label(value: object) -> str:
    """Return a compact analyst-facing label without discarding the model key."""
    key = re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")
    if not key:
        return "n/a"
    return SOC_ALERT_DETECTION_OUTCOME_LABELS.get(key, key.replace("_", " ").title())


def _soc_review_epoch(value: object) -> float:
    try:
        return parse_iso_timestamp(value).timestamp() if value else 0.0
    except (TypeError, ValueError, OverflowError):
        return 0.0


def _soc_review_json(value: object) -> dict:
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(str(value or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _soc_review_list_count(value: object) -> int:
    if isinstance(value, list):
        return len([item for item in value if str(item or "").strip()])
    return 1 if str(value or "").strip() else 0


def _soc_review_defaults() -> dict[str, object]:
    return {
        "analysis_id": "",
        "analysis_confidence": "",
        "analysis_generated_at": "",
        "analysis_evidence_hash": "",
        "primary_outcome": "",
        "primary_confidence": "",
        "primary_event_status": "",
        "primary_detection_validity": "",
        "primary_activity_disposition": "",
        "primary_handling": "",
        "primary_duplicate_of": None,
        "effective_outcome": "",
        "effective_outcome_label": "Not analyzed",
        "effective_confidence": "",
        "freshness_status": "not_analyzed",
        "evidence_updated_at": "",
        "coverage_status": "unknown",
        "evidence_used_count": 0,
        "evidence_gap_count": 0,
        "reviewer_status": "not_requested",
        "reviewer_error": "",
        "reviewer_outcome": "",
        "reviewer_confidence": "",
        "reviewer_agreement": "",
        "automation_authorization": {},
        "material_disagreement": False,
        "disputed_fields": [],
        "final_review_status": "unreviewed",
        "adjudication": None,
    }


SOC_REVIEW_FAILURE_STATUSES = {
    "failed",
    "invalid",
    "invalid_response",
    "not_configured",
    "not_independent",
    "review_required_failed",
}


def _soc_embedded_reviewer(
    response: dict[str, object],
    analysis: dict[str, object] | None = None,
) -> dict[str, object]:
    """Normalize a persisted embedded reviewer result, including failure detail."""
    analysis = analysis if isinstance(analysis, dict) else {}
    embedded = response.get("_second_opinion")
    embedded = embedded if isinstance(embedded, dict) else {}
    comparison = embedded.get("comparison")
    comparison = comparison if isinstance(comparison, dict) else {}
    reviewer_response = embedded.get("response")
    reviewer_response = (
        reviewer_response if isinstance(reviewer_response, dict) else {}
    )
    automation_authorization = embedded.get("automation_authorization")
    automation_authorization = (
        automation_authorization
        if isinstance(automation_authorization, dict)
        else {}
    )
    return {
        "status": embedded.get("status") or "not_requested",
        "reviewer_error": str(embedded.get("error") or "")[:1000],
        "primary_outcome": analysis.get("detection_outcome") or "",
        "primary_confidence": analysis.get("confidence") or "",
        "reviewer_outcome": reviewer_response.get("detection_outcome") or "",
        "reviewer_confidence": reviewer_response.get("confidence") or "",
        "agreement": comparison.get("agreement") or "",
        "automation_authorization": automation_authorization,
        "material_disagreement": bool(comparison.get("material_disagreement")),
        "disputed_fields_json": json.dumps(
            comparison.get("disputed_fields") or []
        ),
    }


def _soc_reviewer_automation_authorization(
    reviewer: dict[str, object],
) -> dict[str, object]:
    """Read the explicit decision, with a medium-confidence legacy fallback."""
    authorization = reviewer.get("automation_authorization")
    authorization = (
        authorization if isinstance(authorization, dict) else {}
    )
    explicit = isinstance(authorization.get("authorized"), bool)
    confidence = str(
        reviewer.get("reviewer_confidence") or ""
    ).strip().lower()
    legacy_denied = bool(
        not explicit
        and confidence != "high"
    )
    return {
        **authorization,
        "authorized": (
            bool(authorization["authorized"])
            if explicit
            else not legacy_denied
        ),
        "explicitly_recorded": explicit,
        "legacy_confidence_fallback": legacy_denied,
    }


def _soc_reviewer_error_select(conn: sqlite3.Connection) -> str:
    """Keep restored pre-migration databases readable."""
    return (
        "reviewer_error"
        if "reviewer_error" in sqlite_table_columns(conn, "ai_second_opinion_runs")
        else "'' AS reviewer_error"
    )


def _soc_review_final_status(
    reviewer: dict[str, object],
    material_disagreement: bool,
    adjudication: dict[str, object] | None,
) -> str:
    """Name consensus only when the independent reviewer explicitly agreed."""
    if adjudication:
        return "adjudicated"
    if material_disagreement:
        return "disputed_pending_human"
    reviewer_status = str(reviewer.get("status") or "").strip().lower()
    if reviewer_status in SOC_REVIEW_FAILURE_STATUSES:
        return "review_required_failed"
    if reviewer_status != "completed":
        return "unreviewed"
    if not _soc_reviewer_automation_authorization(reviewer)["authorized"]:
        return "review_completed_not_authorized"
    if str(reviewer.get("agreement") or "").strip().lower() == "agreement":
        return "model_consensus"
    return "reviewer_advisory"


def soc_alert_apply_review_metadata(
    conn: sqlite3.Connection,
    rows: list[sqlite3.Row | dict],
    metadata: dict[str, dict[str, object]],
    group_by_alert: dict[str, str],
) -> None:
    """Attach current analysis, reviewer, adjudication, freshness, and coverage.

    Every query is page-bounded. Missing migration tables degrade to explicit
    unknown states so an older restored database remains readable.
    """
    if not metadata or not sqlite_table_exists(conn, "ai_analysis_runs"):
        return

    def row_value(row: sqlite3.Row | dict, key: str) -> str:
        if isinstance(row, dict):
            return str(row.get(key) or "").strip()
        return str(row[key] or "").strip() if key in row.keys() else ""

    group_ids = sorted(metadata)
    stable_by_dashboard: dict[str, str] = {}
    if sqlite_table_exists(conn, "alert_group_alias"):
        placeholders = ",".join("?" for _ in group_ids)
        try:
            for item in conn.execute(
                f"""
                SELECT legacy_group_id, stable_group_id
                FROM alert_group_alias
                WHERE legacy_group_id IN ({placeholders})
                """,
                group_ids,
            ):
                stable_by_dashboard[str(item["legacy_group_id"])] = str(item["stable_group_id"] or "")
        except sqlite3.Error:
            pass
    alert_columns = sqlite_table_columns(conn, "alerts")
    if "stable_group_id" in alert_columns and group_by_alert:
        alert_ids = sorted(group_by_alert)
        placeholders = ",".join("?" for _ in alert_ids)
        try:
            for item in conn.execute(
                f"SELECT alert_id, stable_group_id FROM alerts WHERE alert_id IN ({placeholders})",
                alert_ids,
            ):
                dashboard_id = group_by_alert.get(str(item["alert_id"] or ""))
                if dashboard_id and item["stable_group_id"]:
                    stable_by_dashboard[dashboard_id] = str(item["stable_group_id"])
        except sqlite3.Error:
            pass
    dashboards_by_stable: dict[str, list[str]] = {}
    for dashboard_id, stable_id in stable_by_dashboard.items():
        if stable_id:
            dashboards_by_stable.setdefault(stable_id, []).append(dashboard_id)

    run_columns = sqlite_table_columns(conn, "ai_analysis_runs")
    select_columns = [
        column for column in (
            "analysis_id", "group_id", "alert_id", "agent_role", "generated_at",
            "created_at", "model", "detection_outcome", "confidence",
            "evidence_hash", "response_json",
        ) if column in run_columns
    ]
    clauses: list[str] = []
    arguments: list[object] = []
    stable_ids = sorted(dashboards_by_stable)
    representative_ids = sorted(group_by_alert)
    if stable_ids and "group_id" in run_columns:
        clauses.append(f"group_id IN ({','.join('?' for _ in stable_ids)})")
        arguments.extend(stable_ids)
    if representative_ids and "alert_id" in run_columns:
        clauses.append(f"alert_id IN ({','.join('?' for _ in representative_ids)})")
        arguments.extend(representative_ids)
    if not clauses or not select_columns:
        return
    role_filter = (
        " AND COALESCE(NULLIF(agent_role, ''), 'soc-analyst') = 'soc-analyst'"
        if "agent_role" in run_columns else ""
    )
    order_column = "generated_at" if "generated_at" in run_columns else "rowid"
    try:
        analysis_rows = conn.execute(
            f"""
            SELECT {", ".join(select_columns)}
            FROM ai_analysis_runs
            WHERE ({" OR ".join(clauses)}){role_filter}
            ORDER BY {order_column} DESC, rowid DESC
            """,
            arguments,
        ).fetchall()
    except sqlite3.Error:
        analysis_rows = []

    current_analysis: dict[str, dict[str, object]] = {}
    for item in analysis_rows:
        item_dict = dict(item)
        dashboard_ids = list(
            dashboards_by_stable.get(str(item_dict.get("group_id") or ""), [])
        )
        alert_dashboard_id = group_by_alert.get(str(item_dict.get("alert_id") or ""))
        if alert_dashboard_id and alert_dashboard_id not in dashboard_ids:
            dashboard_ids.append(alert_dashboard_id)
        for dashboard_id in dashboard_ids:
            if dashboard_id not in current_analysis:
                current_analysis[dashboard_id] = item_dict

    review_by_analysis: dict[str, dict[str, object]] = {}
    analysis_ids = sorted({
        str(item.get("analysis_id") or "")
        for item in current_analysis.values()
        if item.get("analysis_id")
    })
    if analysis_ids and sqlite_table_exists(conn, "ai_second_opinion_runs"):
        placeholders = ",".join("?" for _ in analysis_ids)
        reviewer_error_select = _soc_reviewer_error_select(conn)
        try:
            for item in conn.execute(
                f"""
                SELECT analysis_id, status, primary_outcome, primary_confidence,
                       reviewer_outcome, reviewer_confidence, agreement,
                       material_disagreement, disputed_fields_json,
                       {reviewer_error_select}, generated_at
                FROM ai_second_opinion_runs
                WHERE analysis_id IN ({placeholders})
                """,
                analysis_ids,
            ):
                review_by_analysis[str(item["analysis_id"])] = dict(item)
        except sqlite3.Error:
            pass

    adjudication_by_analysis_group: dict[tuple[str, str], dict[str, object]] = {}
    if analysis_ids and sqlite_table_exists(conn, "analyst_adjudications"):
        placeholders = ",".join("?" for _ in analysis_ids)
        try:
            records = conn.execute(
                f"""
                SELECT adjudication_id, dashboard_group_id, stable_group_id, analysis_id,
                       outcome_override, confidence, rationale, evidence_gap,
                       next_action, reviewer, event_status, detection_validity,
                       activity_disposition, handling, duplicate_of,
                       case_resolution_reason, created_at
                FROM analyst_adjudications
                WHERE analysis_id IN ({placeholders})
                ORDER BY created_at DESC, rowid DESC
                """,
                analysis_ids,
            ).fetchall()
            for item in records:
                analysis_id = str(item["analysis_id"] or "")
                stable_id = str(item["stable_group_id"] or "")
                key = (analysis_id, stable_id)
                if analysis_id and stable_id and key not in adjudication_by_analysis_group:
                    adjudication_by_analysis_group[key] = dict(item)
        except sqlite3.Error:
            pass

    last_seen_by_group: dict[str, str] = {}
    for row in rows:
        group_key = row_value(row, "group_key")
        dashboard_id = soc_alert_group_id(group_key) if group_key else row_value(row, "group_id")
        if dashboard_id in metadata:
            last_seen_by_group[dashboard_id] = (
                row_value(row, "group_last_seen")
                or row_value(row, "last_seen")
                or row_value(row, "timestamp")
            )

    for dashboard_id, analysis in current_analysis.items():
        target = metadata.get(dashboard_id)
        if target is None:
            continue
        analysis_id = str(analysis.get("analysis_id") or "")
        response = _soc_review_json(analysis.get("response_json"))
        evidence_used = response.get("evidence_used")
        evidence_gaps = response.get("evidence_gaps")
        used_count = _soc_review_list_count(evidence_used)
        gap_count = _soc_review_list_count(evidence_gaps)
        analysis_generated = str(analysis.get("generated_at") or analysis.get("created_at") or "")
        evidence_updated = last_seen_by_group.get(dashboard_id, "")
        freshness = "current"
        if _soc_review_epoch(evidence_updated) > _soc_review_epoch(analysis_generated):
            freshness = "stale"
        coverage = "gaps" if gap_count else ("complete" if used_count else "unknown")

        reviewer = review_by_analysis.get(analysis_id, {})
        embedded_reviewer = _soc_embedded_reviewer(response, analysis)
        if not reviewer:
            reviewer = embedded_reviewer
        else:
            if not reviewer.get("reviewer_error"):
                reviewer["reviewer_error"] = (
                    embedded_reviewer.get("reviewer_error") or ""
                )
            reviewer["automation_authorization"] = (
                embedded_reviewer.get("automation_authorization") or {}
            )
        adjudication = adjudication_by_analysis_group.get((
            analysis_id,
            stable_by_dashboard.get(dashboard_id) or dashboard_id,
        ))
        material = str(
            reviewer.get("material_disagreement") or ""
        ).strip().lower() in {"1", "true", "yes"}
        final_status = _soc_review_final_status(reviewer, material, adjudication)
        primary_outcome = str(
            reviewer.get("primary_outcome")
            or analysis.get("detection_outcome")
            or ""
        )
        primary_confidence = str(
            reviewer.get("primary_confidence")
            or analysis.get("confidence")
            or ""
        )
        effective_outcome = str(
            adjudication.get("outcome_override")
            if adjudication
            else primary_outcome
        )
        effective_confidence = str(
            adjudication.get("confidence")
            if adjudication
            else primary_confidence
        )
        try:
            disputed_fields = json.loads(str(reviewer.get("disputed_fields_json") or "[]"))
        except (TypeError, ValueError, json.JSONDecodeError):
            disputed_fields = []
        if not isinstance(disputed_fields, list):
            disputed_fields = []
        target.update({
            "analysis_id": analysis_id,
            "detection_outcome": str(analysis.get("detection_outcome") or ""),
            "detection_outcome_label": soc_alert_detection_outcome_label(
                analysis.get("detection_outcome")
            ),
            "primary_outcome": primary_outcome,
            "primary_confidence": primary_confidence,
            "primary_event_status": str(response.get("event_status") or ""),
            "primary_detection_validity": str(
                response.get("detection_validity") or ""
            ),
            "primary_activity_disposition": str(
                response.get("activity_disposition") or ""
            ),
            "primary_handling": str(response.get("handling") or ""),
            "primary_duplicate_of": response.get("duplicate_of"),
            "effective_outcome": effective_outcome,
            "effective_outcome_label": soc_alert_detection_outcome_label(
                effective_outcome
            ),
            "effective_confidence": effective_confidence,
            "analysis_confidence": str(analysis.get("confidence") or ""),
            "analysis_generated_at": analysis_generated,
            "analysis_evidence_hash": str(analysis.get("evidence_hash") or ""),
            "freshness_status": freshness,
            "evidence_updated_at": evidence_updated,
            "coverage_status": coverage,
            "evidence_used_count": used_count,
            "evidence_gap_count": gap_count,
            "reviewer_status": str(reviewer.get("status") or "not_requested"),
            "reviewer_error": str(reviewer.get("reviewer_error") or "")[:1000],
            "reviewer_outcome": str(reviewer.get("reviewer_outcome") or ""),
            "reviewer_confidence": str(reviewer.get("reviewer_confidence") or ""),
            "reviewer_agreement": str(reviewer.get("agreement") or ""),
            "automation_authorization": (
                _soc_reviewer_automation_authorization(reviewer)
            ),
            "material_disagreement": material,
            "disputed_fields": disputed_fields[:20],
            "final_review_status": final_status,
            "adjudication": adjudication,
        })


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
            **defaults,
        }
    }
    soc_alert_apply_review_metadata(
        conn,
        [row],
        metadata,
        {alert_id: group_id} if alert_id else {},
    )
    return metadata[group_id]


def soc_alert_group_evidence_metadata(
    conn: sqlite3.Connection | None,
    rows: list[sqlite3.Row | dict],
    ai_artifacts: dict[str, object] | None = None,
    pcap_analysis: dict[str, object] | None = None,
) -> dict[str, dict[str, object]]:
    """Batch group-level PCAP size and latest AI outcome for one API page.

    The dashboard must not issue one SQLite query per row. This helper resolves
    the current page in two bounded queries and falls back to retained analysis
    artifacts when a restored database predates the durable metadata tables.
    """
    def row_value(row: sqlite3.Row | dict, key: str) -> str:
        if isinstance(row, dict):
            return str(row.get(key) or "").strip()
        return str(row[key] or "").strip() if key in row.keys() else ""

    group_by_key: dict[str, str] = {}
    group_by_alert: dict[str, str] = {}
    metadata: dict[str, dict[str, object]] = {}
    for row in rows:
        group_key = row_value(row, "group_key")
        group_id = soc_alert_group_id(group_key) if group_key else row_value(row, "group_id")
        if not group_id:
            continue
        alert_id = row_value(row, "alert_id") or row_value(row, "representative_alert_id")
        metadata[group_id] = {
            "pcap_size_bytes": 0,
            "detection_outcome": "",
            "detection_outcome_label": "n/a",
            **_soc_review_defaults(),
        }
        if group_key:
            group_by_key[group_key] = group_id
        if alert_id:
            group_by_alert[alert_id] = group_id

    ai_artifacts = ai_artifacts if isinstance(ai_artifacts, dict) else {}
    artifact_outcomes = ai_artifacts.get("detection_outcome_by_group_id")
    if isinstance(artifact_outcomes, dict):
        for group_id, record in metadata.items():
            outcome = str(artifact_outcomes.get(group_id) or "").strip()
            if outcome:
                record["detection_outcome"] = outcome
                record["detection_outcome_label"] = soc_alert_detection_outcome_label(outcome)

    pcap_analysis = pcap_analysis if isinstance(pcap_analysis, dict) else {}
    artifact_sizes_by_group = pcap_analysis.get("size_by_group_id")
    artifact_sizes_by_alert = pcap_analysis.get("size_by_alert_id")
    for group_id, record in metadata.items():
        fallback_size = 0
        if isinstance(artifact_sizes_by_group, dict):
            fallback_size = int(artifact_sizes_by_group.get(group_id, 0) or 0)
        if fallback_size <= 0 and isinstance(artifact_sizes_by_alert, dict):
            fallback_size = sum(
                int(artifact_sizes_by_alert.get(alert_id, 0) or 0)
                for alert_id, alert_group_id in group_by_alert.items()
                if alert_group_id == group_id
            )
        record["pcap_size_bytes"] = max(0, fallback_size)

    if conn is None or not metadata:
        return metadata

    def where_terms(columns: list[tuple[str, list[str]]]) -> tuple[str, list[str]]:
        clauses: list[str] = []
        arguments: list[str] = []
        for column, values in columns:
            if not values:
                continue
            clauses.append(f"{column} IN ({','.join('?' for _ in values)})")
            arguments.extend(values)
        return " OR ".join(clauses), arguments

    group_ids = sorted(metadata)
    group_keys = sorted(group_by_key)
    alert_ids = sorted(group_by_alert)

    if sqlite_table_exists(conn, "pcap_requests"):
        where_sql, arguments = where_terms([
            ("group_id", group_ids),
            ("group_key", group_keys),
            ("alert_id", alert_ids),
        ])
        if where_sql:
            try:
                pcap_rows = conn.execute(
                    f"""
                    SELECT request_id, alert_id, group_id, group_key, artifact_path,
                           artifact_sha256, artifact_size_bytes
                    FROM pcap_requests
                    WHERE ({where_sql}) AND COALESCE(artifact_size_bytes, 0) > 0
                    """,
                    arguments,
                ).fetchall()
            except sqlite3.Error:
                pcap_rows = []
            db_sizes: dict[str, int] = {}
            seen_artifacts: set[tuple[str, str]] = set()
            for item in pcap_rows:
                stored_group_id = str(item["group_id"] or "").strip()
                stored_group_key = str(item["group_key"] or "").strip()
                stored_alert_id = str(item["alert_id"] or "").strip()
                group_id = (
                    stored_group_id if stored_group_id in metadata else
                    group_by_key.get(stored_group_key) or group_by_alert.get(stored_alert_id) or ""
                )
                if not group_id:
                    continue
                identity = (
                    str(item["artifact_sha256"] or "").strip()
                    or str(item["artifact_path"] or "").strip()
                    or str(item["request_id"] or "").strip()
                )
                artifact_key = (group_id, identity)
                if not identity or artifact_key in seen_artifacts:
                    continue
                seen_artifacts.add(artifact_key)
                db_sizes[group_id] = db_sizes.get(group_id, 0) + max(0, int(item["artifact_size_bytes"] or 0))
            for group_id, size_bytes in db_sizes.items():
                metadata[group_id]["pcap_size_bytes"] = size_bytes

    if sqlite_table_exists(conn, "ai_analysis_runs"):
        where_sql, arguments = where_terms([("group_id", group_ids), ("alert_id", alert_ids)])
        if where_sql:
            role_filter = ""
            if "agent_role" in sqlite_table_columns(conn, "ai_analysis_runs"):
                # The SOC Alerts outcome column represents SOC triage. A later
                # Incident Responder run must not silently replace that value.
                role_filter = " AND COALESCE(NULLIF(agent_role, ''), 'soc-analyst') = 'soc-analyst'"
            try:
                analysis_rows = conn.execute(
                    f"""
                    SELECT group_id, alert_id, detection_outcome, generated_at, created_at
                    FROM ai_analysis_runs
                    WHERE ({where_sql}) AND COALESCE(detection_outcome, '') <> ''{role_filter}
                    ORDER BY COALESCE(NULLIF(generated_at, ''), created_at) DESC, rowid DESC
                    """,
                    arguments,
                ).fetchall()
            except sqlite3.Error:
                analysis_rows = []
            resolved_groups: set[str] = set()
            for item in analysis_rows:
                stored_group_id = str(item["group_id"] or "").strip()
                stored_alert_id = str(item["alert_id"] or "").strip()
                group_id = stored_group_id if stored_group_id in metadata else group_by_alert.get(stored_alert_id, "")
                if not group_id or group_id in resolved_groups:
                    continue
                outcome = str(item["detection_outcome"] or "").strip()
                if not outcome:
                    continue
                resolved_groups.add(group_id)
                metadata[group_id]["detection_outcome"] = outcome
                metadata[group_id]["detection_outcome_label"] = soc_alert_detection_outcome_label(outcome)

    soc_alert_apply_review_metadata(conn, rows, metadata, group_by_alert)
    return metadata


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
    group_key = row["group_key"]
    group_id = soc_alert_group_id(group_key)
    local_status = statuses.get(group_id, {}) if isinstance(statuses, dict) else {}
    enrichment_json = row.get("enrichment_json") if isinstance(row, dict) else (row["enrichment_json"] if "enrichment_json" in row.keys() else "")
    repeat_count = max(
        int(row["raw_alert_count"] or 0),
        int(row["total_seen_count"] or 0),
        int(row["seen_count"] or 0),
    )
    data = {
        "group_id": group_id,
        "group_key": group_key,
        "representative_alert_id": row["alert_id"],
        "first_seen": row["group_first_seen"] or row["first_seen"],
        "last_seen": row["group_last_seen"] or row["last_seen"],
        "raw_alert_count": int(row["raw_alert_count"] or 0),
        "seen_count": repeat_count,
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
        "source_port": row["source_port"],
        "destination_ip": row["destination_ip"],
        "destination_port": row["destination_port"],
        "payload_size_bytes": int(row["payload_size_bytes"] or 0) if "payload_size_bytes" in row.keys() else 0,
        "transport_protocol": row["transport_protocol"],
        "filter_status": row["filter_status"] or "accepted",
        "filter_reason": row["filter_reason"],
        "suppression_key": row["suppression_key"],
        "analyst_status": local_status.get("status", "open") if isinstance(local_status, dict) else "open",
        "analyst_status_reason": local_status.get("reason", "") if isinstance(local_status, dict) else "",
        "analyst_status_updated_at": local_status.get("updated_at") if isinstance(local_status, dict) else None,
        "analyst_status_updated_by": local_status.get("updated_by", "") if isinstance(local_status, dict) else "",
    }
    data.update(
        soc_alert_group_ai_status(
            row,
            group_id,
            ai_reports,
            ai_artifacts,
            analysis_min_severity,
        )
    )
    data.update(soc_alert_public_enrichment_status(enrichment_json))
    data.update(soc_alert_pcap_status(group_id, row["alert_id"], pcap_analysis or {}, pcap_requests or {}))
    data.update((evidence_metadata or {}).get(group_id, {
        "pcap_size_bytes": 0,
        "detection_outcome": "",
        "detection_outcome_label": "n/a",
        **_soc_review_defaults(),
    }))
    return data


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
        if "release_id" in payload and (
            "cohort_id" in payload or "dispatch_id" in payload
        ):
            request_payload["release_id"] = payload["release_id"]
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
        if "release_id" in payload and (
            "cohort_id" in payload or "dispatch_id" in payload
        ):
            request_payload["release_id"] = payload["release_id"]
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
    payload = payload if isinstance(payload, dict) else {}
    case_status = str(payload.get("status") or "").strip().lower()
    resolution_reason = str(payload.get("resolution_reason") or "").strip()[:2000]
    reviewer = str(payload.get("updated_by") or payload.get("reviewer") or "dashboard").strip()[:100]
    if case_status not in {"open", "in_progress", "resolved"}:
        return soc_alert_api_error("Invalid incident case status")
    if case_status == "resolved" and not resolution_reason:
        return soc_alert_api_error("A resolution reason is required.")
    return _soc_alert_store_mutation(
        "/incidents/status",
        {
            "case_id": case_id,
            "status": case_status,
            "resolution_reason": resolution_reason,
            "updated_by": reviewer,
        },
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
    if "release_id" in payload and (
        "cohort_id" in payload or "dispatch_id" in payload
    ):
        request_payload["release_id"] = payload["release_id"]
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
    run_id = str((query.get("run_id") or [""])[0] or "").strip().lower()
    if run_id and not re.fullmatch(r"irr-[a-z0-9-]{1,64}", run_id):
        return soc_alert_api_error("Invalid incident reanalysis run id")
    try:
        with soc_alert_db_connect() as conn:
            if not sqlite_table_exists(conn, "incident_reanalysis_runs"):
                return 200, {
                    "ok": True,
                    "latest_run": None,
                    "runs": [],
                    "cases": [],
                    "schema_ready": False,
                }
            where_sql = "WHERE run_id = ?" if run_id else ""
            arguments: list[object] = [run_id] if run_id else []
            runs = [
                dict(row)
                for row in conn.execute(
                    f"""
                    SELECT run_id, release_id, scope, status, requested_by, reason,
                           total_count, created_at, updated_at, completed_at
                    FROM incident_reanalysis_runs
                    {where_sql}
                    ORDER BY created_at DESC, run_id DESC LIMIT 20
                    """,
                    arguments,
                ).fetchall()
            ]
            run_ids = [str(item.get("run_id") or "") for item in runs]
            counts_by_run: dict[str, dict[str, int]] = {
                item: {
                    "queued": 0,
                    "running": 0,
                    "completed": 0,
                    "failed": 0,
                    "skipped": 0,
                }
                for item in run_ids
            }
            if run_ids and sqlite_table_exists(conn, "incident_reanalysis_run_cases"):
                placeholders = ",".join("?" for _ in run_ids)
                for row in conn.execute(
                    f"""
                    SELECT run_id, status, COUNT(*) AS count
                    FROM incident_reanalysis_run_cases
                    WHERE run_id IN ({placeholders})
                    GROUP BY run_id, status
                    """,
                    run_ids,
                ).fetchall():
                    run_counts = counts_by_run.get(str(row["run_id"] or ""))
                    if run_counts is not None and str(row["status"] or "") in run_counts:
                        run_counts[str(row["status"])] = int(row["count"] or 0)
            for item in runs:
                item["total_count"] = int(item.get("total_count") or 0)
                item["counts"] = counts_by_run.get(str(item.get("run_id") or ""), {})
            selected_run_id = run_id or (run_ids[0] if run_ids else "")
            cases = []
            if selected_run_id and sqlite_table_exists(conn, "incident_reanalysis_run_cases"):
                cases = [
                    dict(row)
                    for row in conn.execute(
                        """
                        SELECT run_id, case_id, group_id, dashboard_group_id,
                               representative_alert_id, status, skip_reason,
                               latest_error, queued_at, started_at, completed_at,
                               updated_at
                        FROM incident_reanalysis_run_cases
                        WHERE run_id = ?
                        ORDER BY case_id ASC LIMIT 2000
                        """,
                        (selected_run_id,),
                    ).fetchall()
                ]
    except (FileNotFoundError, sqlite3.Error) as exc:
        return soc_alert_api_error(
            f"Incident reanalysis progress unavailable: {exc}",
            HTTPStatus.SERVICE_UNAVAILABLE,
        )
    return 200, {
        "ok": True,
        "latest_run": runs[0] if runs else None,
        "runs": runs,
        "cases": cases,
        "schema_ready": True,
    }


def soc_incident_current_analysis(
    conn: sqlite3.Connection,
    case: dict[str, object],
) -> dict[str, object]:
    """Resolve a case's current IR run without trusting a stale foreign pointer."""
    if not sqlite_table_exists(conn, "ai_analysis_runs"):
        return {}
    run_columns = sqlite_table_columns(conn, "ai_analysis_runs")
    select_columns = [
        column for column in (
            "analysis_id", "group_id", "agent_role", "generated_at", "created_at",
            "model", "detection_outcome", "bluf", "summary", "confidence",
            "evidence_hash", "response_json",
        ) if column in run_columns
    ]
    if not select_columns:
        return {}
    select_sql = ", ".join(select_columns)
    group_id = str(case.get("group_id") or "").strip()
    latest_id = str(case.get("latest_analysis_id") or "").strip()
    if latest_id:
        clauses = ["analysis_id = ?"]
        arguments: list[object] = [latest_id]
        if "group_id" in run_columns:
            clauses.append("group_id = ?")
            arguments.append(group_id)
        if "agent_role" in run_columns:
            clauses.append("agent_role = 'incident-responder'")
        row = conn.execute(
            f"SELECT {select_sql} FROM ai_analysis_runs "
            f"WHERE {' AND '.join(clauses)} LIMIT 1",
            arguments,
        ).fetchone()
        if row:
            return dict(row)
    if not group_id or "group_id" not in run_columns:
        return {}
    clauses = ["group_id = ?"]
    arguments = [group_id]
    if "agent_role" in run_columns:
        clauses.append("agent_role = 'incident-responder'")
    order_columns = [
        column for column in ("generated_at", "created_at") if column in run_columns
    ]
    order_sql = ", ".join(f"{column} DESC" for column in order_columns)
    order_sql = f"{order_sql}, rowid DESC" if order_sql else "rowid DESC"
    row = conn.execute(
        f"SELECT {select_sql} FROM ai_analysis_runs "
        f"WHERE {' AND '.join(clauses)} ORDER BY {order_sql} LIMIT 1",
        arguments,
    ).fetchone()
    return dict(row) if row else {}


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


def soc_incidents_query_response(query: dict[str, list[str]]) -> tuple[int, dict]:
    """Return one bounded page of durable Incident Response cases.

    Case lists intentionally omit raw model JSON and packet evidence. The UI
    loads the existing group-detail endpoint only after an analyst expands a
    row, keeping routine polling inexpensive even with a large case history.
    """
    page = soc_alert_page((query.get("page") or ["1"])[0])
    per_page = soc_alert_limit((query.get("per_page") or ["25"])[0], 25)
    status_filter = str((query.get("status") or ["all"])[0] or "all").strip().lower()
    if status_filter not in {"all", "open", "in_progress", "resolved"}:
        return soc_alert_api_error("Invalid incident status filter")
    sort_key = str(
        (query.get("sort") or ["priority"])[0] or "priority"
    ).strip().lower()
    sort_direction = str(
        (query.get("direction") or ["desc"])[0] or "desc"
    ).strip().lower()
    allowed_sort_keys = {
        "status",
        "severity",
        "escalated",
        "alert",
        "source",
        "destination",
        "destination_port",
        "count",
        "agent",
        "updated",
        "priority",
    }
    if sort_key not in allowed_sort_keys:
        return soc_alert_api_error("Invalid incident sort field")
    if sort_direction not in {"asc", "desc"}:
        return soc_alert_api_error("Invalid incident sort direction")
    try:
        with soc_alert_db_connect() as conn:
            if not sqlite_table_exists(conn, "incident_response_cases"):
                return 200, {
                    "ok": True,
                    "incidents": [],
                    "page": 1,
                    "per_page": per_page,
                    "total": 0,
                    "pages": 1,
                    "status_counts": {},
                    "agent_status_counts": {},
                    "schema_ready": False,
                }
            where_sql = "" if status_filter == "all" else "WHERE c.status = ?"
            arguments: list[object] = [] if status_filter == "all" else [status_filter]
            total = int(conn.execute(
                f"SELECT COUNT(*) FROM incident_response_cases c {where_sql}",
                arguments,
            ).fetchone()[0])
            status_counts = {
                str(row[0] or "unknown"): int(row[1] or 0)
                for row in conn.execute(
                    "SELECT status, COUNT(*) FROM incident_response_cases GROUP BY status"
                ).fetchall()
            }
            agent_status_counts = {
                str(row[0] or "unknown"): int(row[1] or 0)
                for row in conn.execute(
                    "SELECT agent_status, COUNT(*) FROM incident_response_cases GROUP BY agent_status"
                ).fetchall()
            }
            pages = max(1, (total + per_page - 1) // per_page)
            page = min(page, pages)
            offset = (page - 1) * per_page
            summary_ready = sqlite_table_exists(conn, "alert_group_summary")
            direction_sql = "ASC" if sort_direction == "asc" else "DESC"
            common_sort_sql = {
                "status": "c.status",
                "escalated": "c.escalated_at",
                "agent": "c.agent_status",
                "updated": "c.updated_at",
            }
            summary_sort_sql = {
                **common_sort_sql,
                "severity": "COALESCE(g.severity, a.severity, 0)",
                "alert": "COALESCE(g.rule_name, a.rule_name, '') COLLATE NOCASE",
                "source": "COALESCE(g.source_ip, a.source_ip, '') COLLATE NOCASE",
                "destination": (
                    "COALESCE(g.destination_ip, a.destination_ip, '') "
                    "COLLATE NOCASE"
                ),
                "destination_port": (
                    "COALESCE(g.destination_port, a.destination_port, -1)"
                ),
                "count": "COALESCE(g.total_seen_count, a.seen_count, 0)",
            }
            # Older databases without the summary table still support sorting
            # durable case fields. Other requested keys fall back to updated.
            sort_expression = (
                summary_sort_sql.get(sort_key, "c.updated_at")
                if summary_ready
                else common_sort_sql.get(sort_key, "c.updated_at")
            )
            order_sql = (
                "CASE c.status WHEN 'open' THEN 0 "
                "WHEN 'in_progress' THEN 1 ELSE 2 END, "
                "CASE c.agent_status WHEN 'analyzing' THEN 0 "
                "WHEN 'queued' THEN 1 WHEN 'failed' THEN 2 ELSE 3 END, "
                "c.updated_at DESC, c.case_id DESC"
                if sort_key == "priority"
                else (
                    f"{sort_expression} {direction_sql}, "
                    f"c.updated_at DESC, c.case_id DESC"
                )
            )
            case_columns = sqlite_table_columns(conn, "incident_response_cases")
            resolution_reason_sql = (
                "c.resolution_reason" if "resolution_reason" in case_columns
                else "NULL AS resolution_reason"
            )
            resolved_at_sql = (
                "c.resolved_at" if "resolved_at" in case_columns
                else "NULL AS resolved_at"
            )
            resolved_by_sql = (
                "c.resolved_by" if "resolved_by" in case_columns
                else "NULL AS resolved_by"
            )
            if summary_ready:
                rows = conn.execute(
                    f"""
                    SELECT c.case_id, c.group_id, c.dashboard_group_id,
                           c.representative_alert_id, c.status, c.agent_status,
                           c.escalated_at, c.updated_at, c.escalated_by, c.reason,
                           c.latest_analysis_id, c.latest_model,
                           c.latest_generated_at, c.latest_error,
                           {resolution_reason_sql}, {resolved_at_sql}, {resolved_by_sql},
                           COALESCE(g.rule_name, a.rule_name) AS rule_name,
                           COALESCE(g.severity, a.severity) AS severity,
                           COALESCE(g.severity_label, a.severity_label) AS severity_label,
                           COALESCE(g.triage_level, a.triage_level) AS triage_level,
                           COALESCE(g.source_ip, a.source_ip) AS source_ip,
                           COALESCE(g.destination_ip, a.destination_ip) AS destination_ip,
                           COALESCE(g.destination_port, a.destination_port) AS destination_port,
                           COALESCE(g.raw_alert_count, a.seen_count, 0) AS raw_alert_count,
                           COALESCE(g.total_seen_count, a.seen_count, 0) AS total_seen_count,
                           COALESCE(g.first_seen, a.first_seen) AS first_seen,
                           COALESCE(g.last_seen, a.last_seen) AS last_seen
                    FROM incident_response_cases c
                    LEFT JOIN alert_group_summary g ON g.group_id = c.dashboard_group_id
                    LEFT JOIN alerts a ON a.alert_id = c.representative_alert_id
                    {where_sql}
                    ORDER BY {order_sql}
                    LIMIT ? OFFSET ?
                    """,
                    [*arguments, per_page, offset],
                ).fetchall()
            else:
                rows = conn.execute(
                    f"""
                    SELECT c.case_id, c.group_id, c.dashboard_group_id,
                           c.representative_alert_id, c.status, c.agent_status,
                           c.escalated_at, c.updated_at, c.escalated_by, c.reason,
                           c.latest_analysis_id, c.latest_model,
                           c.latest_generated_at, c.latest_error,
                           {resolution_reason_sql}, {resolved_at_sql}, {resolved_by_sql}
                    FROM incident_response_cases c
                    {where_sql}
                    ORDER BY {order_sql}
                    LIMIT ? OFFSET ?
                    """,
                    [*arguments, per_page, offset],
                ).fetchall()

            analyses: dict[str, dict[str, object]] = {}
            run_columns: set[str] = set()
            analysis_ids = sorted({str(row["latest_analysis_id"] or "") for row in rows if row["latest_analysis_id"]})
            if analysis_ids and sqlite_table_exists(conn, "ai_analysis_runs"):
                run_columns = sqlite_table_columns(conn, "ai_analysis_runs")
                analysis_select = [
                    column for column in (
                        "analysis_id", "group_id", "agent_role", "generated_at",
                        "created_at", "model", "detection_outcome", "bluf",
                        "summary", "confidence", "evidence_hash", "response_json",
                    ) if column in run_columns
                ]
                placeholders = ",".join("?" for _ in analysis_ids)
                role_filter = ""
                if "agent_role" in run_columns:
                    role_filter = " AND agent_role = 'incident-responder'"
                for analysis in conn.execute(
                    f"""
                    SELECT {", ".join(analysis_select)}
                    FROM ai_analysis_runs
                    WHERE analysis_id IN ({placeholders}){role_filter}
                    """,
                    analysis_ids,
                ).fetchall():
                    analyses[str(analysis["analysis_id"])] = dict(analysis)

            second_opinions: dict[str, dict[str, object]] = {}
            if analysis_ids and sqlite_table_exists(conn, "ai_second_opinion_runs"):
                placeholders = ",".join("?" for _ in analysis_ids)
                reviewer_error_select = _soc_reviewer_error_select(conn)
                for item in conn.execute(
                    f"""
                    SELECT analysis_id, status, primary_outcome, primary_confidence,
                           reviewer_outcome, reviewer_confidence, agreement,
                           material_disagreement, disputed_fields_json,
                           {reviewer_error_select}, generated_at
                    FROM ai_second_opinion_runs
                    WHERE analysis_id IN ({placeholders})
                    """,
                    analysis_ids,
                ).fetchall():
                    second_opinions[str(item["analysis_id"])] = dict(item)
            adjudications: dict[tuple[str, str], dict[str, object]] = {}
            if analysis_ids and sqlite_table_exists(conn, "analyst_adjudications"):
                placeholders = ",".join("?" for _ in analysis_ids)
                for item in conn.execute(
                    f"""
                    SELECT adjudication_id, dashboard_group_id, case_id, analysis_id,
                           outcome_override, confidence, rationale, evidence_gap,
                           next_action, reviewer, event_status, detection_validity,
                           activity_disposition, handling, duplicate_of,
                           case_resolution_reason, created_at
                    FROM analyst_adjudications
                    WHERE analysis_id IN ({placeholders})
                    ORDER BY created_at DESC, rowid DESC
                    """,
                    analysis_ids,
                ).fetchall():
                    analysis_id = str(item["analysis_id"] or "")
                    case_id = str(item["case_id"] or "")
                    key = (case_id, analysis_id)
                    if case_id and analysis_id and key not in adjudications:
                        adjudications[key] = dict(item)

            incident_inventory, incident_inventory_error = load_asset_inventory_data()
            incidents: list[dict[str, object]] = []
            for row in rows:
                item = dict(row)
                analysis_id = str(item.get("latest_analysis_id") or "")
                analysis = analyses.get(analysis_id, {})
                if (
                    analysis
                    and "group_id" in run_columns
                    and str(analysis.get("group_id") or "") != str(item.get("group_id") or "")
                ):
                    analysis = {}
                if (
                    analysis
                    and "agent_role" in run_columns
                    and str(analysis.get("agent_role") or "") != "incident-responder"
                ):
                    analysis = {}
                fallback_review: dict[str, object] | None = None
                if not analysis and run_columns:
                    analysis = soc_incident_current_analysis(conn, item)
                    if analysis:
                        fallback_response = _soc_review_json(analysis.get("response_json"))
                        fallback_review = soc_incident_review_state(
                            conn,
                            item,
                            analysis,
                            fallback_response,
                        )
                analysis_id = str(analysis.get("analysis_id") or "")
                response = _soc_review_json(analysis.get("response_json"))
                report = response.get("incident_response_report")
                report = report if isinstance(report, dict) else {}
                evidence_gap_count = _soc_review_list_count(report.get("evidence_gaps"))
                query_audit = response.get("_incident_query_audit")
                query_audit = query_audit if isinstance(query_audit, dict) else {}
                coverage_status = (
                    "gaps" if evidence_gap_count or query_audit.get("partial")
                    else ("complete" if query_audit.get("complete") else "unknown")
                )
                analysis_generated = str(
                    analysis.get("generated_at") or ""
                )
                freshness_status = (
                    "stale"
                    if (
                        analysis_generated
                        and _soc_review_epoch(item.get("last_seen"))
                        > _soc_review_epoch(analysis_generated)
                    )
                    else ("current" if analysis_generated else "not_analyzed")
                )
                reviewer = second_opinions.get(analysis_id, {})
                embedded_reviewer = _soc_embedded_reviewer(response, analysis)
                if not reviewer:
                    reviewer = embedded_reviewer
                else:
                    if not reviewer.get("reviewer_error"):
                        reviewer["reviewer_error"] = (
                            embedded_reviewer.get("reviewer_error") or ""
                        )
                    reviewer["automation_authorization"] = (
                        embedded_reviewer.get(
                            "automation_authorization"
                        ) or {}
                    )
                material_disagreement = str(
                    reviewer.get("material_disagreement") or ""
                ).strip().lower() in {"1", "true", "yes"}
                adjudication = adjudications.get((
                    str(item.get("case_id") or ""),
                    analysis_id,
                ))
                final_review_status = _soc_review_final_status(
                    reviewer,
                    material_disagreement,
                    adjudication,
                )
                primary_outcome = str(
                    reviewer.get("primary_outcome")
                    or analysis.get("detection_outcome")
                    or ""
                )
                primary_confidence = str(
                    reviewer.get("primary_confidence")
                    or analysis.get("confidence")
                    or ""
                )
                effective_outcome = str(
                    adjudication.get("outcome_override")
                    if adjudication
                    else primary_outcome
                )
                effective_confidence = str(
                    adjudication.get("confidence")
                    if adjudication
                    else primary_confidence
                )
                if fallback_review:
                    adjudication = fallback_review.get("adjudication")
                    final_review_status = str(
                        fallback_review.get("final_review_status") or "unreviewed"
                    )
                    primary_outcome = str(fallback_review.get("primary_outcome") or "")
                    primary_confidence = str(
                        fallback_review.get("primary_confidence") or ""
                    )
                    effective_outcome = str(
                        fallback_review.get("effective_outcome") or primary_outcome
                    )
                    effective_confidence = str(
                        fallback_review.get("effective_confidence")
                        or primary_confidence
                    )
                    material_disagreement = bool(
                        fallback_review.get("material_disagreement")
                    )
                reviewer_status = (
                    fallback_review.get("reviewer_status")
                    if fallback_review
                    else reviewer.get("status")
                ) or "not_requested"
                agent_display_status, agent_display_label = (
                    soc_incident_agent_display_state(
                        item.get("agent_status"),
                        analysis_id,
                        reviewer_status,
                    )
                )
                count = max(int(item.get("raw_alert_count") or 0), int(item.get("total_seen_count") or 0))
                asset_observed_at = (
                    item.get("last_seen")
                    or item.get("escalated_at")
                    or item.get("updated_at")
                )
                if incident_inventory_error:
                    source_asset = {
                        "status": "inventory_unavailable",
                        "ip": str(item.get("source_ip") or ""),
                    }
                    destination_asset = {
                        "status": "inventory_unavailable",
                        "ip": str(item.get("destination_ip") or ""),
                    }
                else:
                    source_asset = resolve_asset_ip(
                        item.get("source_ip"),
                        asset_observed_at,
                        incident_inventory,
                    )
                    destination_asset = resolve_asset_ip(
                        item.get("destination_ip"),
                        asset_observed_at,
                        incident_inventory,
                    )
                incidents.append({
                    **item,
                    "seen_count": count,
                    "asset_observed_at": str(asset_observed_at or ""),
                    "source_asset": source_asset,
                    "destination_asset": destination_asset,
                    "analysis_id": analysis_id,
                    "analysis_generated_at": analysis.get("generated_at") or "",
                    "analysis_model": analysis.get("model") or "",
                    "detection_outcome": analysis.get("detection_outcome") or "",
                    "primary_outcome": primary_outcome,
                    "primary_confidence": primary_confidence,
                    "primary_event_status": str(response.get("event_status") or ""),
                    "primary_detection_validity": str(
                        response.get("detection_validity") or ""
                    ),
                    "primary_activity_disposition": str(
                        response.get("activity_disposition") or ""
                    ),
                    "primary_handling": str(response.get("handling") or ""),
                    "primary_duplicate_of": response.get("duplicate_of"),
                    "effective_outcome": effective_outcome,
                    "effective_outcome_label": soc_alert_detection_outcome_label(
                        effective_outcome
                    ),
                    "effective_confidence": effective_confidence,
                    "analysis_bluf": analysis.get("bluf") or "",
                    "analysis_summary": analysis.get("summary") or "",
                    "analysis_confidence": analysis.get("confidence") or "",
                    "analysis_evidence_hash": analysis.get("evidence_hash") or "",
                    "analysis_available": bool(analysis_id),
                    "agent_display_status": agent_display_status,
                    "agent_display_label": agent_display_label,
                    "freshness_status": freshness_status,
                    "coverage_status": coverage_status,
                    "evidence_gap_count": evidence_gap_count,
                    "reviewer_status": reviewer_status,
                    "reviewer_error": (
                        fallback_review.get("reviewer_error")
                        if fallback_review
                        else reviewer.get("reviewer_error")
                    ) or "",
                    "reviewer_outcome": (
                        fallback_review.get("reviewer_outcome")
                        if fallback_review
                        else reviewer.get("reviewer_outcome")
                    ) or "",
                    "reviewer_confidence": (
                        fallback_review.get("reviewer_confidence")
                        if fallback_review
                        else reviewer.get("reviewer_confidence")
                    ) or "",
                    "reviewer_agreement": (
                        fallback_review.get("reviewer_agreement")
                        if fallback_review
                        else reviewer.get("agreement")
                    ) or "",
                    "automation_authorization": (
                        fallback_review.get("automation_authorization")
                        if fallback_review
                        else _soc_reviewer_automation_authorization(
                            reviewer
                        )
                    ) or {},
                    "material_disagreement": material_disagreement,
                    "final_review_status": final_review_status,
                    "adjudication": adjudication,
                })
    except (FileNotFoundError, sqlite3.Error) as exc:
        return soc_alert_api_error(f"Incident Response data unavailable: {exc}", 503)
    return 200, {
        "ok": True,
        "incidents": incidents,
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": pages,
        "status_counts": status_counts,
        "agent_status_counts": agent_status_counts,
        "schema_ready": True,
        "sort": sort_key,
        "direction": sort_direction,
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
    review = _soc_review_defaults()
    dashboard_group_id = str(case.get("dashboard_group_id") or "")
    analysis_id = str(analysis.get("analysis_id") or "")
    report = response.get("incident_response_report")
    report = report if isinstance(report, dict) else {}
    analysis_generated = str(analysis.get("generated_at") or "")
    evidence_updated = ""
    if dashboard_group_id and sqlite_table_exists(conn, "alert_group_summary"):
        try:
            row = conn.execute(
                "SELECT last_seen FROM alert_group_summary WHERE group_id = ?",
                (dashboard_group_id,),
            ).fetchone()
            evidence_updated = str(row["last_seen"] or "") if row else ""
        except sqlite3.Error:
            evidence_updated = ""
    query_audit = response.get("_incident_query_audit")
    query_audit = query_audit if isinstance(query_audit, dict) else {}
    gap_count = _soc_review_list_count(report.get("evidence_gaps"))
    used_count = _soc_review_list_count(report.get("evidence_used"))
    coverage = (
        "gaps"
        if gap_count or query_audit.get("partial")
        else "complete"
        if used_count or query_audit.get("complete")
        else "unknown"
    )
    freshness = (
        "stale"
        if analysis_generated
        and _soc_review_epoch(evidence_updated) > _soc_review_epoch(analysis_generated)
        else "current"
        if analysis_generated
        else "not_analyzed"
    )

    reviewer: dict[str, object] = {}
    if analysis_id and sqlite_table_exists(conn, "ai_second_opinion_runs"):
        reviewer_error_select = _soc_reviewer_error_select(conn)
        try:
            row = conn.execute(
                f"""
                SELECT status, primary_outcome, primary_confidence,
                       reviewer_outcome, reviewer_confidence, agreement,
                       material_disagreement, disputed_fields_json,
                       {reviewer_error_select}, generated_at
                FROM ai_second_opinion_runs
                WHERE analysis_id = ?
                """,
                (analysis_id,),
            ).fetchone()
            reviewer = dict(row) if row else {}
        except sqlite3.Error:
            reviewer = {}
    embedded_reviewer = _soc_embedded_reviewer(response, analysis)
    if not reviewer:
        reviewer = embedded_reviewer
    else:
        if not reviewer.get("reviewer_error"):
            reviewer["reviewer_error"] = (
                embedded_reviewer.get("reviewer_error") or ""
            )
        reviewer["automation_authorization"] = (
            embedded_reviewer.get("automation_authorization") or {}
        )
    material = str(reviewer.get("material_disagreement") or "").strip().lower() in {
        "1", "true", "yes",
    }
    try:
        disputed_fields = json.loads(str(reviewer.get("disputed_fields_json") or "[]"))
    except (TypeError, ValueError, json.JSONDecodeError):
        disputed_fields = []
    if not isinstance(disputed_fields, list):
        disputed_fields = []
    adjudication: dict[str, object] | None = None
    if analysis_id and sqlite_table_exists(conn, "analyst_adjudications"):
        try:
            row = conn.execute(
                """
                SELECT adjudication_id, dashboard_group_id, case_id, analysis_id,
                       outcome_override, confidence, rationale, evidence_gap,
                       next_action, reviewer, event_status, detection_validity,
                       activity_disposition, handling, duplicate_of,
                       case_resolution_reason, created_at
                FROM analyst_adjudications
                WHERE analysis_id = ? AND case_id = ?
                ORDER BY created_at DESC, rowid DESC LIMIT 1
                """,
                (analysis_id, str(case.get("case_id") or "")),
            ).fetchone()
            adjudication = dict(row) if row else None
        except sqlite3.Error:
            adjudication = None
    final_status = _soc_review_final_status(reviewer, material, adjudication)
    primary_outcome = str(
        reviewer.get("primary_outcome") or analysis.get("detection_outcome") or ""
    )
    primary_confidence = str(
        reviewer.get("primary_confidence") or analysis.get("confidence") or ""
    )
    effective_outcome = str(
        adjudication.get("outcome_override")
        if adjudication
        else primary_outcome
    )
    effective_confidence = str(
        adjudication.get("confidence")
        if adjudication
        else primary_confidence
    )
    review.update({
        "analysis_id": analysis_id,
        "analysis_generated_at": analysis_generated,
        "analysis_confidence": str(analysis.get("confidence") or ""),
        "analysis_evidence_hash": str(analysis.get("evidence_hash") or ""),
        "primary_outcome": primary_outcome,
        "primary_confidence": primary_confidence,
        "primary_event_status": str(response.get("event_status") or ""),
        "primary_detection_validity": str(
            response.get("detection_validity") or ""
        ),
        "primary_activity_disposition": str(
            response.get("activity_disposition") or ""
        ),
        "primary_handling": str(response.get("handling") or ""),
        "primary_duplicate_of": response.get("duplicate_of"),
        "effective_outcome": effective_outcome,
        "effective_outcome_label": soc_alert_detection_outcome_label(
            effective_outcome
        ),
        "effective_confidence": effective_confidence,
        "freshness_status": freshness,
        "evidence_updated_at": evidence_updated,
        "coverage_status": coverage,
        "evidence_used_count": used_count,
        "evidence_gap_count": gap_count,
        "reviewer_status": str(reviewer.get("status") or "not_requested"),
        "reviewer_error": str(reviewer.get("reviewer_error") or "")[:1000],
        "reviewer_outcome": str(reviewer.get("reviewer_outcome") or ""),
        "reviewer_confidence": str(reviewer.get("reviewer_confidence") or ""),
        "reviewer_agreement": str(reviewer.get("agreement") or ""),
        "automation_authorization": (
            _soc_reviewer_automation_authorization(reviewer)
        ),
        "material_disagreement": material,
        "disputed_fields": disputed_fields[:20],
        "final_review_status": final_status,
        "adjudication": adjudication,
        "case_resolution_reason": str(case.get("resolution_reason") or ""),
        "case_resolved_at": str(case.get("resolved_at") or ""),
        "case_resolved_by": str(case.get("resolved_by") or ""),
    })
    return review


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
    review = review if isinstance(review, dict) else _soc_review_defaults()
    final_status = str(
        review.get("final_review_status")
        or review.get("final_status")
        or "unreviewed"
    )
    status_labels = {
        "disputed_pending_human": "Disputed — human decision required",
        "review_required_failed": "Independent review failed — human decision required",
        "review_completed_not_authorized": (
            "Review completed — automation not authorized; human decision required"
        ),
        "adjudicated": "Adjudicated",
        "model_consensus": "Primary and reviewer agree",
        "reviewer_advisory": "Reviewer advisory — no material disagreement",
        "unreviewed": "Not independently reviewed",
    }
    primary_outcome = str(
        review.get("primary_outcome")
        or review.get("detection_outcome")
        or ""
    )
    primary_confidence = str(
        review.get("primary_confidence")
        or review.get("analysis_confidence")
        or ""
    )
    primary_event_status = str(review.get("primary_event_status") or "")
    primary_detection_validity = str(
        review.get("primary_detection_validity") or ""
    )
    primary_activity_disposition = str(
        review.get("primary_activity_disposition") or ""
    )
    primary_handling = str(review.get("primary_handling") or "")
    primary_duplicate_of = str(review.get("primary_duplicate_of") or "")
    reviewer_outcome = str(review.get("reviewer_outcome") or "")
    reviewer_confidence = str(review.get("reviewer_confidence") or "")
    reviewer_error = str(review.get("reviewer_error") or "").strip()[:1000]
    agreement = str(
        review.get("reviewer_agreement")
        or review.get("agreement")
        or ""
    )
    freshness = str(review.get("freshness_status") or "unknown")
    coverage = str(review.get("coverage_status") or "unknown")
    analysis_id = str(review.get("analysis_id") or "")
    adjudication = review.get("adjudication")
    adjudication = adjudication if isinstance(adjudication, dict) else {}
    disputed_fields = review.get("disputed_fields")
    disputed_fields = disputed_fields if isinstance(disputed_fields, list) else []
    disputed = final_status == "disputed_pending_human"
    review_failed = final_status == "review_required_failed"
    review_not_authorized = (
        final_status == "review_completed_not_authorized"
    )
    role_attr = (
        ' role="alert"'
        if disputed or review_failed or review_not_authorized
        else ""
    )
    disabled_attr = (
        ' disabled title="Run an analysis before recording an analyst decision"'
        if not analysis_id
        else ""
    )
    comparison = (
        '<div class="analyst-review-comparison">'
        f'<div><b>Primary</b><span>{_incident_html_text(soc_alert_detection_outcome_label(primary_outcome))}'
        f' · {_incident_html_text(primary_confidence or "confidence unknown")}</span></div>'
        f'<div><b>Independent reviewer</b><span>{_incident_html_text(soc_alert_detection_outcome_label(reviewer_outcome))}'
        f' · {_incident_html_text(reviewer_confidence or "confidence unknown")}</span></div>'
        "</div>"
        if reviewer_outcome or agreement
        else '<p class="analyst-review-empty">No completed independent reviewer result is attached.</p>'
    )
    disputed_fields_html = (
        '<p class="analyst-review-disputed-fields"><b>Disputed fields:</b> '
        + ", ".join(_incident_html_text(item) for item in disputed_fields[:20])
        + "</p>"
        if disputed_fields
        else ""
    )
    reviewer_error_html = (
        '<p class="analyst-review-failure"><b>Reviewer failure:</b> '
        + _incident_html_text(reviewer_error)
        + "</p>"
        if reviewer_error
        else ""
    )
    adjudication_html = ""
    if adjudication:
        evidence_gap = str(adjudication.get("evidence_gap") or "").strip()
        next_action = str(adjudication.get("next_action") or "").strip()
        resolution_reason = str(
            adjudication.get("case_resolution_reason") or ""
        ).strip()
        factored_verdict = [
            (label, str(adjudication.get(key) or "").strip())
            for key, label in (
                ("event_status", "Event"),
                ("detection_validity", "Detection"),
                ("activity_disposition", "Activity"),
                ("handling", "Handling"),
                ("duplicate_of", "Duplicate of"),
            )
            if str(adjudication.get(key) or "").strip()
        ]
        factored_html = (
            '<div class="analyst-adjudication-factors"><b>Analyst-confirmed verdict factors:</b><ul>'
            + "".join(
                f"<li>{_incident_html_text(label)}: {_incident_html_text(value)}</li>"
                for label, value in factored_verdict
            )
            + "</ul></div>"
            if factored_verdict
            else ""
        )
        adjudication_html = (
            '<div class="analyst-adjudication-summary">'
            f'<b>Final analyst decision:</b> {_incident_html_text(soc_alert_detection_outcome_label(adjudication.get("outcome_override")))}'
            f' · {_incident_html_text(adjudication.get("confidence") or "confidence unknown")}'
            f'<p>{_incident_html_text(adjudication.get("rationale"))}</p>'
            + (
                f'<p><b>Evidence gap:</b> {_incident_html_text(evidence_gap)}</p>'
                if evidence_gap else ""
            )
            + (
                f'<p><b>Next action:</b> {_incident_html_text(next_action)}</p>'
                if next_action else ""
            )
            + (
                f'<p><b>Case resolution:</b> {_incident_html_text(resolution_reason)}</p>'
                if resolution_reason else ""
            )
            + factored_html
            + f'<small>Reviewed by {_incident_html_text(adjudication.get("reviewer"))} at '
            f'{_incident_html_text(adjudication.get("created_at"))}</small>'
            "</div>"
        )
    case_resolution_html = ""
    case_resolution_reason = str(
        review.get("case_resolution_reason") or ""
    ).strip()
    if case_resolution_reason:
        case_resolution_html = (
            '<div class="analyst-case-resolution">'
            f'<b>Resolved:</b> {_incident_html_text(case_resolution_reason)}'
            f'<small> by {_incident_html_text(review.get("case_resolved_by"))} at '
            f'{_incident_html_text(review.get("case_resolved_at"))}</small>'
            "</div>"
        )
    return (
        f'<section class="analyst-review-panel review-status-{html.escape(final_status, quote=True)}" '
        f'data-review-group="{html.escape(group_id, quote=True)}" '
        f'data-review-case="{html.escape(case_id, quote=True)}" '
        f'data-review-analysis="{html.escape(analysis_id, quote=True)}" '
        f'data-review-primary="{html.escape(primary_outcome, quote=True)}" '
        f'data-review-event-status="{html.escape(primary_event_status, quote=True)}" '
        f'data-review-detection-validity="{html.escape(primary_detection_validity, quote=True)}" '
        f'data-review-activity-disposition="{html.escape(primary_activity_disposition, quote=True)}" '
        f'data-review-handling="{html.escape(primary_handling, quote=True)}" '
        f'data-review-duplicate-of="{html.escape(primary_duplicate_of, quote=True)}" '
        f"{role_attr}>"
        '<div class="analyst-review-heading">'
        '<div><span class="analyst-review-eyebrow">Human validation</span>'
        f'<h3>{html.escape(status_labels.get(final_status, final_status.replace("_", " ").title()))}</h3></div>'
        '<div class="analyst-review-badges">'
        f'<span class="review-badge review-freshness-{html.escape(freshness, quote=True)}">Freshness: {html.escape(freshness.replace("_", " "))}</span>'
        f'<span class="review-badge review-coverage-{html.escape(coverage, quote=True)}">Coverage: {html.escape(coverage.replace("_", " "))}</span>'
        "</div></div>"
        f"{comparison}{reviewer_error_html}{disputed_fields_html}{adjudication_html}{case_resolution_html}"
        f'<button class="analyst-adjudicate-button" type="button" data-open-adjudication{disabled_attr}>'
        f'{"Resolve required review" if disputed or review_failed or review_not_authorized else "Record analyst decision"}'
        "</button>"
        "</section>"
    )


def _investigation_purpose_text(value: object) -> str:
    purpose = str(value or "").strip()
    labels = {
        "validate_detection": "Validate whether the observed event matches the triggering detection.",
        "establish_timeline": "Establish the order and timing of related activity.",
        "correlate_observable": "Correlate an exact trusted observable across reviewed telemetry.",
        "measure_prevalence": "Measure how often the exact activity appears in the authorized window.",
        "identify_related_activity": "Identify related activity that could expand or narrow incident scope.",
        "test_benign_hypothesis": "Test a specific benign explanation against the available telemetry.",
    }
    return labels.get(purpose, purpose)


def render_investigation_query_audit_html(
    response: dict[str, object],
    report: dict[str, object],
) -> tuple[str, int]:
    """Render broker-owned iterative pivot records, never model-authored queries."""
    audit = response.get("_investigation_query_audit")
    if not isinstance(audit, dict):
        return "", 0
    rounds = audit.get("rounds") if isinstance(audit.get("rounds"), list) else []
    query_blocks: list[str] = []
    position = 0
    for round_record in rounds[:12]:
        if not isinstance(round_record, dict):
            continue
        round_number = _incident_nonnegative_int(round_record.get("round"))
        trusted_queries = (
            round_record.get("trusted_queries")
            if isinstance(round_record.get("trusted_queries"), list)
            else []
        )
        for query in trusted_queries[:12]:
            if not isinstance(query, dict):
                continue
            position += 1
            backend = str(query.get("backend") or query.get("dialect") or "broker").strip().lower()
            subject = str(
                query.get("pack")
                or query.get("operation")
                or query.get("target_alias")
                or query.get("query_id")
                or "reviewed pivot"
            ).strip()
            title = f"Pivot {position} (round {round_number or 1}): {backend.upper()} · {subject}"
            purpose = _investigation_purpose_text(query.get("purpose"))
            digest = str(
                query.get("query_digest")
                or query.get("execution_digest")
                or query.get("request_digest")
                or ""
            ).strip()
            linked_finding = _incident_query_linked_finding(report, digest)
            window = query.get("window") if isinstance(query.get("window"), dict) else {}
            meta: list[str] = [
                f'<span><b>Status:</b> {_incident_html_text(query.get("status") or "unknown")}</span>',
                f'<span><b>Digest:</b> <code>{_incident_html_text(digest)}</code></span>',
            ]
            if window:
                meta.append(
                    f'<span><b>Window:</b> {_incident_html_text(window.get("start"))} '
                    f'to {_incident_html_text(window.get("end"))}</span>'
                )
            if query.get("total_hits") is not None or query.get("returned_hits") is not None:
                meta.append(
                    f'<span><b>Hits:</b> {_incident_nonnegative_int(query.get("total_hits"))} total / '
                    f'{_incident_nonnegative_int(query.get("returned_hits"))} returned</span>'
                )
            if query.get("total_rows") is not None or query.get("returned_rows") is not None:
                meta.append(
                    f'<span><b>Rows:</b> {_incident_nonnegative_int(query.get("total_rows"))} total / '
                    f'{_incident_nonnegative_int(query.get("returned_rows"))} returned</span>'
                )
            if (
                query.get("candidate_records_scanned") is not None
                or query.get("records_returned") is not None
            ):
                meta.append(
                    f'<span><b>Records:</b> {_incident_nonnegative_int(query.get("candidate_records_scanned"))} '
                    f'scanned / {_incident_nonnegative_int(query.get("records_returned"))} returned</span>'
                )
            semantics = query.get("semantics") or query.get("execution_semantics")
            if semantics:
                meta.append(
                    f'<span><b>Semantics:</b> {_incident_html_text(semantics)}</span>'
                )
            if query.get("execution_backend"):
                meta.append(
                    f'<span><b>Executor:</b> {_incident_html_text(query.get("execution_backend"))}</span>'
                )
            if any(
                bool(query.get(key))
                for key in ("truncated", "result_truncated", "index_scan_truncated")
            ):
                meta.append("<span><b>Truncated:</b> true</span>")

            code_blocks: list[str] = []

            def add_code_block(heading: str, value: object, *, json_value: bool = False) -> None:
                if value in (None, "", {}, []):
                    return
                rendered = (
                    json.dumps(value, indent=2, sort_keys=True, default=str)
                    if json_value
                    else str(value)
                )
                code_blocks.extend([
                    f"<h5>{html.escape(heading)}</h5>",
                    f'<pre class="ir-query-code"><code>{html.escape(rendered)}</code></pre>',
                ])

            add_code_block("OQL (analyst-readable equivalent)", query.get("oql_equivalent"))
            add_code_block("KQL (analyst-readable equivalent)", query.get("kql_equivalent"))
            add_code_block(
                "Elasticsearch Query DSL (exact executed request)",
                query.get("query_dsl"),
                json_value=True,
            )
            if backend == "osquery":
                add_code_block(
                    "OSquery SQL (exact executed live query)",
                    query.get("query"),
                )
            if backend in {"pcap", "zeek"}:
                structured_request = {
                    key: query.get(key)
                    for key in ("operation", "filters", "indicator", "limit")
                    if query.get(key) not in (None, "", {}, [])
                }
                add_code_block(
                    "Structured PCAP/Zeek request (exact broker input)",
                    structured_request,
                    json_value=True,
                )
            error = str(query.get("error") or "").strip()
            error_html = (
                f'<p class="ir-query-error"><b>Error:</b> {html.escape(error)}</p>'
                if error
                else ""
            )
            query_blocks.append(
                f'<article class="ir-query-record" '
                f'data-query-purpose="{html.escape(purpose, quote=True)}" '
                f'data-query-finding="{html.escape(linked_finding, quote=True)}">'
                f"<h4>{html.escape(title)}</h4>"
                f'<div class="ir-query-meta">{"".join(meta)}</div>'
                f'{"".join(code_blocks)}{error_html}'
                "</article>"
            )

    rounds_completed = _incident_nonnegative_int(audit.get("rounds_completed"))
    admitted = _incident_nonnegative_int(audit.get("queries_admitted"))
    ignored = _incident_nonnegative_int(audit.get("requests_ignored_or_over_budget"))
    section = (
        '<section class="ir-query-audit">'
        "<h3>Interactive Investigation Pivot Audit</h3>"
        '<div class="ir-analysis-meta">'
        f'<span><b>Contract:</b> {_incident_html_text(audit.get("query_contract"))}</span>'
        f'<span><b>Provider neutral:</b> {_incident_html_text(audit.get("provider_neutral", True))}</span>'
        f'<span><b>Model route:</b> {_incident_html_text(audit.get("model_route"))}</span>'
        f"<span><b>Rounds:</b> {rounds_completed}</span>"
        f"<span><b>Admitted:</b> {admitted}</span>"
        f"<span><b>Rejected/over budget:</b> {ignored}</span>"
        "</div>"
        + (
            "".join(query_blocks)
            if query_blocks
            else "<p>No broker-authorized pivot produced a presentation-ready execution record.</p>"
        )
        + "</section>"
    )
    return section, len(query_blocks)


def render_incident_response_report_html(
    case: dict[str, object],
    response: dict[str, object],
    analysis: dict[str, object],
    review: dict[str, object] | None = None,
) -> tuple[str, int]:
    """Render a fact-grounded responder report and immutable query audit.

    All model and collector values are escaped here. Query DSL is formatted as
    text, never interpreted as markup, and comes from the runner's trusted
    post-inference audit rather than model prose.
    """
    report = response.get("incident_response_report")
    report = report if isinstance(report, dict) else {}
    metadata = (
        '<div class="ir-analysis-meta">'
        f'<span><b>Case:</b> {_incident_html_text(case.get("case_id"))}</span>'
        f'<span><b>Generated:</b> {_incident_html_text(analysis.get("generated_at"))}</span>'
        f'<span><b>Model:</b> {_incident_html_text(analysis.get("model"))}</span>'
        f'<span><b>Confidence:</b> {_incident_html_text(report.get("confidence") or analysis.get("confidence"))}</span>'
        + (
            f'<span><b>Resolution:</b> {_incident_html_text(case.get("resolution_reason"))}</span>'
            f'<span><b>Resolved by:</b> {_incident_html_text(case.get("resolved_by"))}</span>'
            f'<span><b>Resolved at:</b> {_incident_html_text(case.get("resolved_at"))}</span>'
            if case.get("resolution_reason")
            else ""
        )
        + "</div>"
    )
    if not report:
        state = str(case.get("agent_status") or "queued").replace("_", " ")
        error = str(case.get("latest_error") or "").strip()
        message = error if error else f"Incident Responder analysis is {state}."
        return (
            '<section class="ir-investigation-report">'
            "<h3>Incident Response Investigation</h3>"
            f"{metadata}<p class=\"ir-analysis-empty\">{html.escape(message)}</p>"
            "</section>",
            0,
        )

    timeline_rows = []
    timeline = report.get("factual_timeline") if isinstance(report.get("factual_timeline"), list) else []
    for event in timeline[:200]:
        if not isinstance(event, dict):
            continue
        timeline_rows.append(
            "<tr>"
            f"<td>{_incident_html_text(event.get('timestamp'))}</td>"
            f"<td>{_incident_html_text(event.get('event'))}</td>"
            f"<td>{_incident_html_text(event.get('source_pack') or 'supplied evidence')}</td>"
            f"<td><code>{_incident_html_text(event.get('query_digest'))}</code></td>"
            f"<td>{_incident_html_text(event.get('confidence') or 'low')}</td>"
            "</tr>"
        )
    timeline_html = (
        '<div class="ir-timeline-wrap"><table class="ir-timeline-table"><thead><tr>'
        "<th>Time</th><th>Observed event</th><th>Evidence source</th><th>Query digest</th><th>Confidence</th>"
        f"</tr></thead><tbody>{''.join(timeline_rows)}</tbody></table></div>"
        if timeline_rows
        else "<p>No fact-grounded timeline entries were returned.</p>"
    )

    sections = [
        _incident_report_section("Executive BLUF", f"<p>{_incident_html_text(report.get('executive_bluf'))}</p>"),
        _incident_report_section(
            "Detection Outcome Reasoning",
            f"<p>{_incident_html_text(report.get('detection_outcome_reasoning'))}</p>",
        ),
        _incident_report_section("Scope", f"<p>{_incident_html_text(report.get('scope'))}</p>"),
        _incident_report_section("Constraints", _incident_html_list(report.get("constraints"), "No explicit constraints were recorded.")),
        _incident_report_section("Affected Systems", _incident_html_list(report.get("affected_systems"))),
        _incident_report_section("Methodology", _incident_html_list(report.get("methodology"))),
        _incident_report_section("Factual Timeline", timeline_html),
    ]
    for title, key in (
        ("Security Onion Findings", "security_onion_findings"),
        ("OSquery Findings", "osquery_findings"),
        ("PCAP Findings", "pcap_findings"),
        ("Host Findings", "host_findings"),
        ("Correlation Findings", "correlation_findings"),
        ("Containment Recommendations", "containment_recommendations"),
        ("Eradication Recommendations", "eradication_recommendations"),
        ("Recovery Recommendations", "recovery_recommendations"),
        ("Follow-up Queries", "follow_up_queries"),
        ("Evidence Gaps", "evidence_gaps"),
    ):
        sections.append(_incident_report_section(title, _incident_html_list(report.get(key))))
    sections.append(
        _incident_report_section(
            "Conclusion",
            f"<p>{_incident_html_text(report.get('conclusion'))}</p>"
            f'<p><b>Confidence:</b> {_incident_html_text(report.get("confidence") or "low")}</p>',
        )
    )

    audit = response.get("_incident_query_audit")
    audit = audit if isinstance(audit, dict) else {}
    query_blocks = []
    queries = audit.get("queries") if isinstance(audit.get("queries"), list) else []
    for position, query in enumerate(queries[:100], 1):
        if not isinstance(query, dict):
            continue
        window = query.get("window") if isinstance(query.get("window"), dict) else {}
        dsl = query.get("query_dsl") if isinstance(query.get("query_dsl"), dict) else {}
        dsl_text = html.escape(json.dumps(dsl, indent=2, sort_keys=True, default=str))
        linked_finding = _incident_query_linked_finding(report, query.get("query_digest"))
        query_blocks.append(
            f'<article class="ir-query-record" data-query-finding="{html.escape(linked_finding, quote=True)}">'
            f'<h4>Query {position}: {_incident_html_text(query.get("pack") or "evidence pack")}</h4>'
            '<div class="ir-query-meta">'
            f'<span><b>Status:</b> {_incident_html_text(query.get("status") or "unknown")}</span>'
            f'<span><b>Digest:</b> <code>{_incident_html_text(query.get("query_digest"))}</code></span>'
            f'<span><b>Window:</b> {_incident_html_text(window.get("start"))} to {_incident_html_text(window.get("end"))}</span>'
            f'<span><b>Hits:</b> {_incident_nonnegative_int(query.get("total_hits"))} total / '
            f'{_incident_nonnegative_int(query.get("returned_hits"))} returned</span>'
            "</div>"
            "<h5>KQL (analyst-readable equivalent)</h5>"
            f'<pre class="ir-query-code"><code>{_incident_html_text(query.get("kql_equivalent"))}</code></pre>'
            "<h5>Elasticsearch Query DSL (exact executed request)</h5>"
            f'<pre class="ir-query-code"><code>{dsl_text}</code></pre>'
            "</article>"
        )
    audit_html = (
        '<section class="ir-query-audit">'
        "<h3>Security Onion Query Audit</h3>"
        '<div class="ir-analysis-meta">'
        f'<span><b>Source:</b> {_incident_html_text(audit.get("trusted_source"))}</span>'
        f'<span><b>Read only:</b> {_incident_html_text(audit.get("read_only", True))}</span>'
        f'<span><b>Complete:</b> {_incident_html_text(audit.get("complete", False))}</span>'
        f'<span><b>Partial:</b> {_incident_html_text(audit.get("partial", True))}</span>'
        "</div>"
        + ("".join(query_blocks) if query_blocks else "<p>No restricted Security Onion queries were recorded.</p>")
        + "</section>"
    )

    osquery_audit = response.get("_incident_osquery_audit")
    osquery_audit = osquery_audit if isinstance(osquery_audit, dict) else {}
    osquery_blocks = []
    osquery_queries = (
        osquery_audit.get("queries")
        if isinstance(osquery_audit.get("queries"), list)
        else []
    )
    for position, query in enumerate(osquery_queries[:32], 1):
        if not isinstance(query, dict):
            continue
        rows = query.get("rows_preview") if isinstance(query.get("rows_preview"), list) else []
        rows_text = html.escape(json.dumps(rows[:25], indent=2, sort_keys=True, default=str))
        linked_finding = _incident_query_linked_finding(report, query.get("query_digest"))
        error = str(query.get("error") or "").strip()
        error_html = (
            f'<p class="ir-query-error"><b>Error:</b> {html.escape(error)}</p>'
            if error
            else ""
        )
        preview_html = (
            "<h5>Bounded Result Preview</h5>"
            f'<pre class="ir-query-code"><code>{rows_text}</code></pre>'
            if rows
            else "<p>No rows were returned by this reviewed pack.</p>"
        )
        osquery_blocks.append(
            f'<article class="ir-query-record" data-query-finding="{html.escape(linked_finding, quote=True)}">'
            f'<h4>OSquery {position}: {_incident_html_text(query.get("pack") or "reviewed pack")}</h4>'
            '<div class="ir-query-meta">'
            f'<span><b>Target:</b> {_incident_html_text(query.get("target"))}</span>'
            f'<span><b>Status:</b> {_incident_html_text(query.get("status") or "unknown")}</span>'
            f'<span><b>Digest:</b> <code>{_incident_html_text(query.get("query_digest"))}</code></span>'
            f'<span><b>Rows:</b> {_incident_nonnegative_int(query.get("total_rows"))} total / '
            f'{_incident_nonnegative_int(query.get("returned_rows"))} returned</span>'
            f'<span><b>Duration:</b> {_incident_nonnegative_int(query.get("duration_ms"))} ms</span>'
            f'<span><b>Truncated:</b> {_incident_html_text(query.get("truncated", False))}</span>'
            "</div>"
            "<h5>OSquery SQL (exact executed command)</h5>"
            f'<pre class="ir-query-code"><code>{_incident_html_text(query.get("query"))}</code></pre>'
            f"{preview_html}{error_html}"
            "</article>"
        )
    osquery_audit_html = (
        '<section class="ir-query-audit">'
        "<h3>Security Onion Appliance OSQuery Snapshot Audit</h3>"
        '<div class="ir-analysis-meta">'
        f'<span><b>Source:</b> {_incident_html_text(osquery_audit.get("trusted_source"))}</span>'
        f'<span><b>Read only:</b> {_incident_html_text(osquery_audit.get("read_only", True))}</span>'
        f'<span><b>Contract:</b> {_incident_html_text(osquery_audit.get("query_contract"))}</span>'
        "</div>"
        + (
            "".join(osquery_blocks)
            if osquery_blocks
            else "<p>No validated Security Onion appliance OSquery snapshots were recorded.</p>"
        )
        + "</section>"
    )

    live_osquery_audit = response.get("_incident_live_osquery_audit")
    live_osquery_audit = live_osquery_audit if isinstance(live_osquery_audit, dict) else {}
    live_osquery_blocks = []
    live_osquery_queries = (
        live_osquery_audit.get("queries")
        if isinstance(live_osquery_audit.get("queries"), list)
        else []
    )
    for position, query in enumerate(live_osquery_queries[:32], 1):
        if not isinstance(query, dict):
            continue
        rows = query.get("rows_preview") if isinstance(query.get("rows_preview"), list) else []
        rows_text = html.escape(json.dumps(rows[:25], indent=2, sort_keys=True, default=str))
        linked_finding = _incident_query_linked_finding(report, query.get("query_digest"))
        error = str(query.get("error") or "").strip()
        error_html = (
            f'<p class="ir-query-error"><b>Error:</b> {html.escape(error)}</p>'
            if error
            else ""
        )
        preview_html = (
            "<h5>Bounded Result Preview</h5>"
            f'<pre class="ir-query-code"><code>{rows_text}</code></pre>'
            if rows
            else "<p>No rows were returned by this endpoint query.</p>"
        )
        purpose = str(query.get("purpose") or "").strip()
        live_osquery_blocks.append(
            f'<article class="ir-query-record" '
            f'data-query-purpose="{html.escape(purpose, quote=True)}" '
            f'data-query-finding="{html.escape(linked_finding, quote=True)}">'
            f'<h4>Endpoint Query {position}: {_incident_html_text(query.get("target_alias") or "configured endpoint")}</h4>'
            '<div class="ir-query-meta">'
            f'<span><b>Target:</b> {_incident_html_text(query.get("target_alias"))}</span>'
            f'<span><b>Status:</b> {_incident_html_text(query.get("status") or "unknown")}</span>'
            f'<span><b>Digest:</b> <code>{_incident_html_text(query.get("query_digest"))}</code></span>'
            f'<span><b>Rows:</b> {_incident_nonnegative_int(query.get("total_rows"))} total / '
            f'{_incident_nonnegative_int(query.get("returned_rows"))} returned</span>'
            f'<span><b>Duration:</b> {_incident_nonnegative_int(query.get("duration_ms"))} ms</span>'
            f'<span><b>Truncated:</b> {_incident_html_text(query.get("truncated", False))}</span>'
            "</div>"
            "<h5>OSquery SQL (exact executed live query)</h5>"
            f'<pre class="ir-query-code"><code>{_incident_html_text(query.get("query"))}</code></pre>'
            f"{preview_html}{error_html}"
            "</article>"
        )
    live_osquery_error = str(live_osquery_audit.get("error") or "").strip()
    live_osquery_error_html = (
        f'<p class="ir-query-error"><b>Collection note:</b> {html.escape(live_osquery_error)}</p>'
        if live_osquery_error
        else ""
    )
    live_osquery_audit_html = (
        '<section class="ir-query-audit">'
        "<h3>Endpoint Live OSQuery Audit</h3>"
        '<div class="ir-analysis-meta">'
        f'<span><b>Source:</b> {_incident_html_text(live_osquery_audit.get("trusted_source"))}</span>'
        f'<span><b>Read only:</b> {_incident_html_text(live_osquery_audit.get("read_only", True))}</span>'
        f'<span><b>Complete:</b> {_incident_html_text(live_osquery_audit.get("complete", False))}</span>'
        f'<span><b>Contract:</b> {_incident_html_text(live_osquery_audit.get("query_contract"))}</span>'
        "</div>"
        + live_osquery_error_html
        + (
            "".join(live_osquery_blocks)
            if live_osquery_blocks
            else "<p>No endpoint live OSquery batch was executed for this investigation.</p>"
        )
        + "</section>"
    )
    investigation_audit_html, investigation_query_count = (
        render_investigation_query_audit_html(response, report)
    )
    return (
        render_analyst_review_panel(
            review,
            group_id=str(case.get("dashboard_group_id") or ""),
            case_id=str(case.get("case_id") or ""),
        )
        +
        '<section class="ir-investigation-report">'
        "<h3>Incident Response Investigation</h3>"
        f"{metadata}{''.join(sections)}"
        "</section>"
        f"{audit_html}{osquery_audit_html}{live_osquery_audit_html}{investigation_audit_html}",
        (
            len(query_blocks)
            + len(osquery_blocks)
            + len(live_osquery_blocks)
            + investigation_query_count
        ),
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
            if not sqlite_table_exists(conn, "incident_response_cases"):
                return soc_alert_api_error("Incident Response schema is unavailable", 503)
            case_row = conn.execute(
                "SELECT * FROM incident_response_cases WHERE case_id = ?", (case_id,)
            ).fetchone()
            if not case_row:
                return soc_alert_api_error("Incident case not found", 404)
            case = dict(case_row)
            run_columns = sqlite_table_columns(conn, "ai_analysis_runs")
            analysis: dict[str, object] = {}
            response: dict[str, object] = {}
            prior_analysis: dict[str, object] = {}
            prior_response: dict[str, object] = {}
            review = _soc_review_defaults()
            if run_columns:
                select_columns = [
                    column for column in (
                        "analysis_id", "group_id", "agent_role", "generated_at", "model",
                        "detection_outcome", "bluf", "summary", "confidence",
                        "evidence_hash", "response_json",
                    ) if column in run_columns
                ]
                select_sql = ", ".join(select_columns)
                analysis = soc_incident_current_analysis(conn, case)
                if analysis.get("response_json"):
                    try:
                        parsed = json.loads(str(analysis["response_json"]))
                        response = parsed if isinstance(parsed, dict) else {}
                    except (TypeError, ValueError, json.JSONDecodeError):
                        response = {}
                if "group_id" in run_columns and "agent_role" in run_columns:
                    row = conn.execute(
                        f"SELECT {select_sql} FROM ai_analysis_runs "
                        "WHERE group_id = ? AND agent_role = 'soc-analyst' "
                        "ORDER BY generated_at DESC LIMIT 1",
                        (case.get("group_id"),),
                    ).fetchone()
                    prior_analysis = dict(row) if row else {}
                    if prior_analysis.get("response_json"):
                        try:
                            parsed = json.loads(str(prior_analysis["response_json"]))
                            prior_response = parsed if isinstance(parsed, dict) else {}
                        except (TypeError, ValueError, json.JSONDecodeError):
                            prior_response = {}
            review = soc_incident_review_state(conn, case, analysis, response)
    except (FileNotFoundError, sqlite3.Error) as exc:
        return soc_alert_api_error(f"Incident Response detail unavailable: {exc}", 503)

    incident_html, query_count = render_incident_response_report_html(
        case,
        response,
        analysis,
        review,
    )
    prior_html = render_prior_soc_analysis_html(prior_response, prior_analysis)
    return 200, {
        "ok": True,
        "case_id": case_id,
        "agent_status": case.get("agent_status") or "queued",
        "analysis_available": bool(response.get("incident_response_report")),
        "query_count": query_count,
        "review": review,
        "incident_html": incident_html,
        "prior_ai_html": prior_html,
    }


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
    ai_reports = soc_alert_static_ai_reports()
    ai_artifacts = soc_alert_page_ai_artifact_context(snapshot.page_rows)
    ai_settings_response = read_soc_ai_settings()
    ai_settings = (
        ai_settings_response.get("settings", {})
        if isinstance(ai_settings_response, dict)
        else {}
    )
    analysis_min_severity = str(
        ai_settings.get("soc_analyst_analysis_min_severity")
        or "informational"
    )
    pcap_analysis = soc_alert_pcap_analysis_index()
    try:
        with soc_alert_db_connect() as conn:
            pcap_requests = soc_alert_pcap_request_statuses(conn, snapshot.page_rows)
            evidence_metadata = soc_alert_group_evidence_metadata(
                conn,
                snapshot.page_rows,
                ai_artifacts,
                pcap_analysis,
            )
    except Exception:
        pcap_requests = {}
        evidence_metadata = soc_alert_group_evidence_metadata(
            None,
            snapshot.page_rows,
            ai_artifacts,
            pcap_analysis,
        )
    return {
        "ok": True,
        "source": source,
        "mode": "grouped",
        "db_path": str(SOC_ALERT_STORE_DB),
        "count": len(snapshot.page_rows),
        "total_matching": snapshot.total_matching,
        "status_counts": snapshot.status_counts,
        "active_total": snapshot.active_total,
        "active_severity_counts": snapshot.active_severity_counts,
        "active_highest_severity": snapshot.active_highest_severity,
        "severity_counts": snapshot.severity_counts,
        "highest_severity": snapshot.highest_severity,
        "top_endpoints": snapshot.top_endpoints,
        "limit": limit,
        "page": snapshot.current_page,
        "page_size": limit,
        "total_pages": snapshot.total_pages,
        "sort": sort_key,
        "direction": sort_direction,
        "next_cursor": snapshot.next_cursor,
        "alerts": [
            soc_alert_group_row_to_api(
                row,
                snapshot.statuses,
                ai_reports,
                pcap_analysis,
                pcap_requests,
                ai_artifacts,
                evidence_metadata,
                analysis_min_severity,
            )
            for row in snapshot.page_rows
        ],
    }


def soc_alerts_summary_query_response(query: dict[str, list[str]]) -> tuple[int, dict] | None:
    """Serve grouped alert rows from alert_group_summary when available.

    The fallback grouped query below remains useful for old/restored databases,
    but this summary path keeps the hot dashboard API off full-table window
    functions during normal operation.
    """
    since = parse_soc_alert_since((query.get("since") or [""])[0])
    levels = soc_alert_level_names((query.get("level") or query.get("levels") or [""])[0])
    filter_status = str((query.get("filter_status") or query.get("status") or [""])[0]).strip().lower()
    analyst_status = str((query.get("analyst_status") or [""])[0]).strip().lower()
    q = str((query.get("q") or query.get("search") or [""])[0]).strip()
    cursor_seen, cursor_id = soc_alert_cursor_parts((query.get("cursor") or [""])[0])
    limit = soc_alert_limit((query.get("limit") or [""])[0])
    requested_page = soc_alert_page((query.get("page") or ["1"])[0])
    sort_key, sort_direction, order_sql = soc_alert_sort_clause(query)

    where = []
    args: list[object] = []
    if since:
        where.append("last_seen >= ?")
        args.append(since)
    if levels:
        placeholders = ",".join("?" for _ in levels)
        where.append(f"lower(coalesce(triage_level, severity_label, 'unknown')) in ({placeholders})")
        args.extend(levels)
    if filter_status in {"accepted", "suppressed", "dropped", "duplicate"}:
        where.append("lower(coalesce(filter_status, 'accepted')) = ?")
        args.append(filter_status)
    if q:
        where.append(
            "("
            "rule_name like ? or source_ip like ? or destination_ip like ? or "
            "event_dataset like ? or representative_alert_id like ? or group_key like ?"
            ")"
        )
        like = f"%{q}%"
        args.extend([like, like, like, like, like, like])
    where_sql = " WHERE " + " AND ".join(where) if where else ""
    sql = f"""
        SELECT group_id, group_key, representative_alert_id AS alert_id,
               first_seen AS group_first_seen, first_seen,
               last_seen AS group_last_seen, last_seen,
               raw_alert_count, total_seen_count, total_seen_count AS seen_count,
               timestamp, rule_name, event_dataset, severity, severity_label,
               source_ip, source_port, destination_ip, destination_port,
               transport_protocol, traffic_direction, triage_score, triage_level,
               routing, filter_status, filter_reason, suppression_key,
               (
                 SELECT LENGTH(COALESCE(alert_json, ''))
                 FROM alerts
                 WHERE alert_id = alert_group_summary.representative_alert_id
                 LIMIT 1
               ) AS payload_size_bytes
        FROM alert_group_summary
        {where_sql}
        ORDER BY {order_sql}
    """
    try:
        with soc_alert_db_connect() as conn:
            if not soc_alert_group_summary_available(conn):
                return None
            rows = conn.execute(sql, args).fetchall()
            manually_escalated_group_ids = soc_alert_manually_escalated_group_ids(conn)
    except Exception as e:
        return soc_alert_api_error(str(e), 503)

    snapshot = soc_alert_group_query_snapshot(
        rows,
        analyst_status=analyst_status,
        cursor_seen=cursor_seen,
        cursor_id=cursor_id,
        limit=limit,
        requested_page=requested_page,
        excluded_group_ids=manually_escalated_group_ids,
    )
    return 200, soc_alert_group_query_payload(
        source="sqlite-summary",
        snapshot=snapshot,
        limit=limit,
        sort_key=sort_key,
        sort_direction=sort_direction,
    )


def soc_alerts_query_response(query: dict[str, list[str]]) -> tuple[int, dict]:
    summary_response = soc_alerts_summary_query_response(query)
    if summary_response is not None:
        return summary_response

    since = parse_soc_alert_since((query.get("since") or [""])[0])
    levels = soc_alert_level_names((query.get("level") or query.get("levels") or [""])[0])
    filter_status = str((query.get("filter_status") or query.get("status") or [""])[0]).strip().lower()
    analyst_status = str((query.get("analyst_status") or [""])[0]).strip().lower()
    q = str((query.get("q") or query.get("search") or [""])[0]).strip()
    cursor_seen, cursor_id = soc_alert_cursor_parts((query.get("cursor") or [""])[0])
    limit = soc_alert_limit((query.get("limit") or [""])[0])
    requested_page = soc_alert_page((query.get("page") or ["1"])[0])
    sort_key, sort_direction, order_sql = soc_alert_sort_clause(query, fallback=True)

    where = []
    args: list[object] = []
    if since:
        where.append("last_seen >= ?")
        args.append(since)
    if levels:
        placeholders = ",".join("?" for _ in levels)
        where.append(f"lower(coalesce(triage_level, severity_label, 'unknown')) in ({placeholders})")
        args.extend(levels)
    if filter_status in {"accepted", "suppressed", "dropped"}:
        where.append("lower(coalesce(filter_status, 'accepted')) = ?")
        args.append(filter_status)
    if q:
        where.append("(rule_name like ? or source_ip like ? or destination_ip like ? or alert_json like ?)")
        like = f"%{q}%"
        args.extend([like, like, like, like])
    where_sql = " where " + " and ".join(where) if where else ""
    group_expr = soc_alert_group_key_sql()
    sql = f"""
        WITH ranked AS (
          SELECT alert_id, first_seen, last_seen, seen_count, timestamp, rule_name,
                 event_dataset, severity, severity_label, source_ip, source_port,
                 destination_ip, destination_port, transport_protocol,
                 traffic_direction, triage_score, triage_level, routing, filter_status,
                 filter_reason, suppression_key, alert_json, enrichment_json,
                 LENGTH(COALESCE(alert_json, '')) AS payload_size_bytes,
                 {group_expr} AS group_key,
                 COUNT(*) OVER (PARTITION BY {group_expr}) AS raw_alert_count,
                 SUM(MAX(1, COALESCE(seen_count, 1))) OVER (PARTITION BY {group_expr}) AS total_seen_count,
                 MIN(first_seen) OVER (PARTITION BY {group_expr}) AS group_first_seen,
                 MAX(last_seen) OVER (PARTITION BY {group_expr}) AS group_last_seen,
                 ROW_NUMBER() OVER (
                   PARTITION BY {group_expr}
                   ORDER BY replace(replace(COALESCE(last_seen, timestamp, first_seen), 'T', ' '), 'Z', '') DESC,
                            alert_id DESC
                 ) AS rn
          FROM alerts
          {where_sql}
        )
        SELECT *
        FROM ranked
        WHERE rn = 1
        ORDER BY {order_sql}
    """
    try:
        with soc_alert_db_connect() as conn:
            rows = conn.execute(sql, args).fetchall()
            manually_escalated_group_ids = soc_alert_manually_escalated_group_ids(conn)
    except Exception as e:
        return soc_alert_api_error(str(e), 503)

    snapshot = soc_alert_group_query_snapshot(
        rows,
        analyst_status=analyst_status,
        cursor_seen=cursor_seen,
        cursor_id=cursor_id,
        limit=limit,
        requested_page=requested_page,
        excluded_group_ids=manually_escalated_group_ids,
    )
    return 200, soc_alert_group_query_payload(
        source="sqlite",
        snapshot=snapshot,
        limit=limit,
        sort_key=sort_key,
        sort_direction=sort_direction,
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
    }


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
        if parsed.path in ("/", "/index.html", "/healthz", "/api/reports", "/api/admin/session-status", "/api/asset-inventory", "/api/dhcp-asset-discovery", "/api/software-inventory", "/api/llm-analysis/current", "/api/llm-analysis/logs", "/api/system-health/beacons", "/api/soc-alerts", "/api/soc-alerts/events", "/api/soc-alerts/metrics", "/api/soc-alerts/suppressions", "/api/soc-alerts/status", "/api/soc-incidents", "/api/soc-incidents/reanalysis-runs", "/api/soc-settings/agent-memory", "/api/soc-settings/ai-model", "/api/soc-settings/ollama-models", "/api/resource-library/favorites", "/admin", "/admin/login") or parsed.path in SOC_SETTINGS_PROMPT_API_PATHS or (parsed.path.startswith("/api/soc-incidents/") and parsed.path.endswith("/detail")) or (parsed.path.startswith("/api/soc-alerts/") and not parsed.path.endswith(("/ack", "/escalate"))):
            if parsed.path == "/admin" and not self._admin_authenticated():
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/admin/login")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return
            self.send_response(HTTPStatus.OK)
            content_type = "text/html; charset=utf-8" if parsed.path in ("/", "/index.html", "/admin", "/admin/login") else "application/json; charset=utf-8"
            if parsed.path == "/api/soc-alerts/events":
                content_type = "text/event-stream; charset=utf-8"
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
        else:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.end_headers()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        is_asset_write = parsed.path in {
            "/api/assets/promote-dhcp",
            "/api/assets/approve-dhcp-ip-change",
        }
        is_incident_reanalysis = (
            parsed.path == "/api/soc-incidents/reanalyze-all"
            or (
                parsed.path.startswith("/api/soc-incidents/")
                and parsed.path.endswith("/reanalyze")
            )
        )
        is_review_write = (
            parsed.path.startswith("/api/soc-alerts/")
            and parsed.path.endswith("/adjudicate")
        ) or (
            parsed.path.startswith("/api/soc-incidents/")
            and parsed.path.endswith(("/adjudicate", "/status"))
        )
        if parsed.path not in ("/admin/login", "/admin/logout", "/admin/action", "/api/admin/start-service", "/api/soc-alerts/status", "/api/soc-settings/ai-model", "/api/soc-settings/agent-model", "/api/resource-library/remove", "/api/resource-library/tags", "/api/resource-library/rename", "/api/resource-library/favorite") and parsed.path not in SOC_SETTINGS_PROMPT_API_PATHS and not (parsed.path.startswith("/api/soc-alerts/") and parsed.path.endswith(("/ack", "/pcap", "/analyze", "/escalate"))) and not is_review_write and not is_incident_reanalysis and not is_asset_write:
            return self._send(HTTPStatus.NOT_FOUND, b"Not found", "text/plain; charset=utf-8")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 50000:
            if parsed.path == "/api/admin/start-service":
                return self._send(HTTPStatus.BAD_REQUEST, json.dumps({"ok": False, "error": "Invalid request size"}).encode(), "application/json; charset=utf-8")
            if parsed.path in ("/api/soc-alerts/status", "/api/soc-settings/ai-model", "/api/soc-settings/agent-model") or parsed.path in SOC_SETTINGS_PROMPT_API_PATHS or (parsed.path.startswith("/api/soc-alerts/") and parsed.path.endswith(("/ack", "/pcap", "/analyze", "/escalate"))) or is_review_write or is_incident_reanalysis or is_asset_write:
                return self._send(HTTPStatus.BAD_REQUEST, json.dumps({"ok": False, "error": "Invalid request size"}).encode(), "application/json; charset=utf-8")
            if parsed.path.startswith("/api/resource-library/"):
                return self._send(HTTPStatus.BAD_REQUEST, json.dumps({"ok": False, "error": "Invalid request size"}).encode(), "application/json; charset=utf-8")
            if parsed.path == "/admin/action" and self._admin_authenticated():
                return self._send(HTTPStatus.BAD_REQUEST, render_admin_dashboard("Invalid admin action request size.", True))
            return self._send(HTTPStatus.BAD_REQUEST, render_admin_login("Invalid request size.", True))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        if is_asset_write:
            if (
                not self._admin_authenticated()
                or not self._soc_review_write_authorized()
            ):
                return self._send(
                    HTTPStatus.FORBIDDEN,
                    json.dumps({
                        "ok": False,
                        "error": (
                            "Sign in to Onion Sentinel Administration before "
                            "approving asset inventory changes."
                        ),
                    }).encode(),
                    "application/json; charset=utf-8",
                )
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                payload = None
            if parsed.path == "/api/assets/promote-dhcp":
                status, data = asset_dhcp_promotion_response(payload)
            else:
                status, data = asset_dhcp_ip_change_response(payload)
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
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                payload = None
            if not isinstance(payload, dict):
                return self._send(
                    HTTPStatus.BAD_REQUEST,
                    json.dumps({
                        "ok": False,
                        "error": "Request body must be a JSON object.",
                    }).encode(),
                    "application/json; charset=utf-8",
                )
            if parsed.path == "/api/soc-incidents/reanalyze-all":
                status, data = soc_incident_bulk_reanalysis_response(payload)
            else:
                encoded_id = parsed.path[
                    len("/api/soc-incidents/"):-len("/reanalyze")
                ].strip("/")
                status, data = soc_incident_reanalysis_response(
                    unquote(encoded_id),
                    payload,
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
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                return self._send(
                    HTTPStatus.BAD_REQUEST,
                    json.dumps({"ok": False, "error": "Request body must be valid JSON."}).encode(),
                    "application/json; charset=utf-8",
                )
            if not isinstance(payload, dict):
                return self._send(
                    HTTPStatus.BAD_REQUEST,
                    json.dumps({"ok": False, "error": "Request body must be a JSON object."}).encode(),
                    "application/json; charset=utf-8",
                )
            if parsed.path.startswith("/api/soc-alerts/"):
                encoded_id = parsed.path[
                    len("/api/soc-alerts/"):-len("/adjudicate")
                ].strip("/")
                status, data = soc_alert_adjudication_response(unquote(encoded_id), payload)
            elif parsed.path.endswith("/adjudicate"):
                encoded_id = parsed.path[
                    len("/api/soc-incidents/"):-len("/adjudicate")
                ].strip("/")
                status, data = soc_incident_adjudication_response(unquote(encoded_id), payload)
            else:
                encoded_id = parsed.path[
                    len("/api/soc-incidents/"):-len("/status")
                ].strip("/")
                status, data = soc_incident_status_response(unquote(encoded_id), payload)
            if status < 400:
                SOC_ALERT_RESPONSE_CACHE.clear()
            return self._send(
                status,
                json.dumps(data, indent=2).encode(),
                "application/json; charset=utf-8",
            )
        if parsed.path.startswith("/api/soc-alerts/") and parsed.path.endswith("/ack"):
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {}
            encoded_id = parsed.path[len("/api/soc-alerts/"):-len("/ack")].strip("/")
            status, data = ack_soc_alert_store_id(unquote(encoded_id), payload)
            if status < 400:
                SOC_ALERT_RESPONSE_CACHE.clear()
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path.startswith("/api/soc-alerts/") and parsed.path.endswith("/pcap"):
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {}
            encoded_id = parsed.path[len("/api/soc-alerts/"):-len("/pcap")].strip("/")
            status, data = soc_alert_pcap_request_response(unquote(encoded_id), payload)
            if status < 400:
                SOC_ALERT_RESPONSE_CACHE.clear()
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path.startswith("/api/soc-alerts/") and parsed.path.endswith("/analyze"):
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {}
            encoded_id = parsed.path[len("/api/soc-alerts/"):-len("/analyze")].strip("/")
            status, data = soc_alert_queue_analysis_response(unquote(encoded_id), payload)
            if status < 400:
                SOC_ALERT_RESPONSE_CACHE.clear()
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path.startswith("/api/soc-alerts/") and parsed.path.endswith("/escalate"):
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {}
            encoded_id = parsed.path[len("/api/soc-alerts/"):-len("/escalate")].strip("/")
            status, data = soc_alert_escalate_response(unquote(encoded_id), payload)
            if status < 400:
                SOC_ALERT_RESPONSE_CACHE.clear()
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path == "/api/soc-alerts/status":
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {}
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
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {}
            if not self._soc_settings_write_authorized():
                return self._send(HTTPStatus.FORBIDDEN, json.dumps({"ok": False, "error": "Sign in to Administration before saving SOC settings."}).encode(), "application/json; charset=utf-8")
            ok, data = save_settings_prompt(parsed.path, payload.get("prompt", ""))
            return self._send(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path == "/api/soc-settings/ai-model":
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {}
            if not self._soc_settings_write_authorized():
                return self._send(HTTPStatus.FORBIDDEN, json.dumps({"ok": False, "error": "Sign in to Administration before saving SOC settings."}).encode(), "application/json; charset=utf-8")
            ok, data = save_soc_ai_settings(payload)
            return self._send(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path == "/api/soc-settings/agent-model":
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {}
            if not self._soc_settings_write_authorized():
                return self._send(HTTPStatus.FORBIDDEN, json.dumps({"ok": False, "error": "Sign in to Administration before saving SOC settings."}).encode(), "application/json; charset=utf-8")
            ok, data = save_soc_agent_model(payload)
            return self._send(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path == "/api/admin/start-service":
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {}
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
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {}
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
        if path == "/" or path == "/index.html":
            reports = scan_reports()
            body = render_home(reports, self.server.server_address[0], self.server.server_address[1])
            return self._send(HTTPStatus.OK, body)
        if path == "/admin/login":
            if self._admin_authenticated():
                return self._redirect("/admin")
            return self._send(HTTPStatus.OK, render_admin_login())
        if path == "/admin":
            if not self._require_admin_auth():
                return None
            admin_message = (query.get("admin_msg") or [""])[0]
            admin_error = (query.get("admin_error") or [""])[0]
            return self._send(HTTPStatus.OK, render_admin_dashboard(admin_message or admin_error, bool(admin_error)))
        if path == "/healthz":
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
        if path == "/api/admin/session-status":
            data = {
                "ok": True,
                "authenticated": self._admin_authenticated(),
            }
            return self._send(
                HTTPStatus.OK,
                json.dumps(data, indent=2).encode(),
                "application/json; charset=utf-8",
            )
        if path == "/api/admin/service-status":
            if not self._admin_authenticated():
                return self._send(HTTPStatus.FORBIDDEN, json.dumps({"ok": False, "error": "Sign in before reading Administration service status."}).encode(), "application/json; charset=utf-8")
            return self._send(HTTPStatus.OK, json.dumps(defang_admin_service_json(admin_service_statuses()), indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/resource-library/favorites":
            data = {"ok": True, "favorites": resource_favorites()}
            return self._send(HTTPStatus.OK, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/system-health/beacons":
            data = n8n_beacon_history_response(query)
            return self._send(HTTPStatus.OK, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/asset-inventory":
            status, data = asset_inventory_response(query=query)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/dhcp-asset-discovery":
            status, data = dhcp_asset_discovery_response()
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/software-inventory":
            status, data = software_inventory_response(query=query)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/llm-analysis/current":
            return self._send(HTTPStatus.OK, json.dumps(read_llm_current_analysis(), indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/llm-analysis/logs":
            return self._send(HTTPStatus.OK, json.dumps(llm_analysis_logs_response(query), indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/soc-alerts/events":
            return self._send_soc_alert_events()
        if path == "/api/soc-alerts/status":
            return self._send(HTTPStatus.OK, json.dumps(soc_alert_status_response(), indent=2).encode(), "application/json; charset=utf-8")
        if path in SOC_SETTINGS_PROMPT_API_PATHS:
            data = read_settings_prompt(path)
            return self._send(HTTPStatus.OK if data.get("ok") else HTTPStatus.INTERNAL_SERVER_ERROR, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/soc-settings/agent-memory":
            status, data = read_agent_memory((query.get("key") or [""])[0])
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/soc-settings/ai-model":
            data = read_soc_ai_settings()
            return self._send(HTTPStatus.OK if data.get("ok") else HTTPStatus.INTERNAL_SERVER_ERROR, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/soc-settings/ollama-models":
            force_refresh = (query.get("refresh") or [""])[0].strip().lower() in {"1", "true", "yes"}
            return self._send(HTTPStatus.OK, json.dumps(ollama_models_response(force_refresh), indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/soc-alerts":
            status, payload = cached_soc_alerts_query_response(query)
            return self._send(status, payload, "application/json; charset=utf-8")
        if path == "/api/soc-alerts/metrics":
            status, data = soc_alert_metrics_response(query)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/soc-alerts/suppressions":
            status, data = soc_alert_suppressions_response(query)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/soc-incidents":
            status, data = soc_incidents_query_response(query)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/soc-incidents/reanalysis-runs":
            status, data = soc_incident_reanalysis_runs_response(query)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path.startswith("/api/soc-incidents/") and path.endswith("/adjudications"):
            case_id = unquote(
                path[len("/api/soc-incidents/"):-len("/adjudications")].strip("/")
            )
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
        if path.startswith("/api/soc-incidents/") and path.endswith("/detail"):
            case_id = unquote(path[len("/api/soc-incidents/"):-len("/detail")].strip("/"))
            status, data = soc_incident_detail_response(case_id)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path.startswith("/api/soc-alerts/") and path.endswith("/adjudications"):
            group_id = unquote(
                path[len("/api/soc-alerts/"):-len("/adjudications")].strip("/")
            )
            try:
                limit = int((query.get("limit") or ["25"])[0])
            except (TypeError, ValueError):
                limit = 25
            status, data = soc_adjudication_history_response(group_id, limit=limit)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path.startswith("/api/soc-alerts/") and path.endswith("/detail"):
            group_id = unquote(path[len("/api/soc-alerts/"):-len("/detail")].strip("/"))
            status, data = soc_alert_detail_fragment_response(group_id)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path.startswith("/api/soc-alerts/"):
            alert_id = unquote(path[len("/api/soc-alerts/"):].strip("/"))
            status, data = soc_alert_detail_response(alert_id)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/resource-library/action-status":
            action_id = (query.get("id") or [""])[0]
            if not re.fullmatch(r"[a-f0-9-]{32,36}", action_id):
                return self._send(HTTPStatus.BAD_REQUEST, json.dumps({"ok": False, "error": "Invalid action id"}).encode(), "application/json; charset=utf-8")
            status_path = RESOURCE_LIBRARY_ACTION_STATUS_DIR / f"{action_id}.json"
            if not status_path.exists():
                return self._send(HTTPStatus.OK, json.dumps({"ok": True, "state": "pending"}).encode(), "application/json; charset=utf-8")
            return self._send(HTTPStatus.OK, status_path.read_bytes(), "application/json; charset=utf-8")
        # The report catalog is unrelated to the SOC APIs above and requires a
        # recursive filesystem walk. Defer it until a catalog/view route needs
        # it so concurrent alert refreshes do not rescan hundreds of reports.
        reports = scan_reports()
        if path == "/api/reports":
            data = [{"id": r.rid, "title": r.title, "path": r.rel, "category": r.category, "mtime": r.mtime, "size": r.size} for r in reports]
            return self._send(HTTPStatus.OK, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        metric_routes = {
            "/metrics/system-uptime": lambda: render_system_uptime_detail(),
            "/metrics/updates": lambda: render_prioritized_updates_detail(),
            "/metrics/macos-updates": lambda: render_macos_updates_detail(),
            "/metrics/hermes-backups": lambda: render_hermes_backups_detail(),
            "/metrics/local-disk": lambda: render_local_disk_detail(),
            "/metrics/portal-update": lambda: render_portal_update_detail(reports),
        }
        if path in metric_routes:
            return self._send(HTTPStatus.OK, metric_routes[path]())
        # Backward-compatible static aliases for Forest Room 5. These make old
        # /open/<id> pages, cached pages, and direct LAN asset URLs resolve their
        # relative image/PDF links instead of showing alt-text-only blank cards.
        asset_prefixes = ["/forest_room5_assets/", "/open/forest_room5_assets/"]
        for ap in asset_prefixes:
            if path.startswith(ap):
                rel_asset = unquote(path[len(ap):])
                base = (HOME / "report_portal" / "library" / "Prototype Web App" / "forest_room5_assets").resolve()
                target = (base / rel_asset).resolve()
                try:
                    target.relative_to(base)
                except ValueError:
                    return self._send(HTTPStatus.FORBIDDEN, b"Forbidden", "text/plain; charset=utf-8")
                return self._serve_file(target)
        if path in ("/qr_landing_source.pdf", "/open/qr_landing_source.pdf"):
            return self._serve_file(HOME / "report_portal" / "library" / "Prototype Web App" / "qr_landing_source.pdf")
        if path.startswith("/view/"):
            parts = path[len("/view/"):].split("/", 1)
            rid = unquote(parts[0]).strip()
            report = self.reports_by_id().get(rid)
            if not report:
                return self._send(HTTPStatus.NOT_FOUND, b"Report not found", "text/plain; charset=utf-8")
            asset_rel = unquote(parts[1]) if len(parts) > 1 else ""
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
        for prefix, download in (("/open/", False), ("/download/", True)):
            if path.startswith(prefix):
                rid = unquote(path[len(prefix):]).strip("/")
                report = self.reports_by_id().get(rid)
                if not report:
                    return self._send(HTTPStatus.NOT_FOUND, b"Report not found", "text/plain; charset=utf-8")
                if not download:
                    return self._redirect(f"/view/{report.rid}/")
                # The mirrored Threat Intel index.html is a "Latest" shim with a relative
                # meta-refresh. When served at /open/<id>, that relative URL resolves under
                # /open/ and breaks. For Open Report, serve the newest real brief directly.
                if not download and report.category == "Threat Intel" and report.is_index:
                    latest = latest_threat_report(reports)
                    if latest:
                        report = latest
                try:
                    body = report.path.read_bytes()
                except Exception as e:
                    return self._send(HTTPStatus.INTERNAL_SERVER_ERROR, str(e).encode(), "text/plain; charset=utf-8")
                ctype = mimetypes.guess_type(report.path.name)[0] or "text/html; charset=utf-8"
                extra = {}
                if download:
                    extra["Content-Disposition"] = f"attachment; filename={quote(report.path.name)}"
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
