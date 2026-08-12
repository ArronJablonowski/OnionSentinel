"""Host paths, bounded caches, and policy constants for the report portal."""
from __future__ import annotations

import os
import re
import threading
from pathlib import Path

import software_inventory
from artifact_cache import ArtifactCache
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
SOC_ALERT_STORE_API_URL = os.environ.get(
    "SOC_ALERT_STORE_API_URL", "http://127.0.0.1:8787"
).rstrip("/")
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
SOC_ALERT_DASHBOARD_DIR = (
    HOME / "report_portal" / "library" / "Cybersecurity" / "SOC Alerts"
)
SOC_ALERT_DETAIL_DIR = SOC_ALERT_DASHBOARD_DIR / "details"
SOC_ALERT_STATIC_STATUS_FILE = SOC_ALERT_DASHBOARD_DIR / "soc-alerts-status.json"
SOC_ALERT_N8N_BEACON_FILE = SOC_ALERT_DASHBOARD_DIR / "n8n-beacon.json"
SOC_ALERT_N8N_BEACON_HISTORY_FILE = SOC_ALERT_DASHBOARD_DIR / "n8n-beacon-history.json"
SOC_ALERT_PCAP_WORKFLOW_STATE_FILE = SOC_ALERT_DASHBOARD_DIR / "pcap-workflow-state.json"
SOC_ALERT_PCAP_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "pcap-analysis"
SOC_ALERT_PCAP_ARTIFACT_DIR = HOME / "n8n-local" / "pcap-evidence" / "artifacts"
SOC_ALERT_AI_PROMPT_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-prompts"
SOC_ALERT_AI_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-analysis"
SOC_ALERT_AI_PROMPT_BUILDER = (
    HOME / "n8n-local" / "bin" / "build-ai-investigation-prompt.py"
)
SOC_ALERT_LLM_ANALYSIS_LOG_DIR = (
    HOME / "n8n-local" / "soc-alerts" / "llm-analysis-logs"
)
SOC_ALERT_LLM_ANALYSIS_LOG_FILE = SOC_ALERT_LLM_ANALYSIS_LOG_DIR / "llm-analysis-log.jsonl"
SOC_ALERT_LLM_ANALYSIS_CURRENT_FILE = SOC_ALERT_LLM_ANALYSIS_LOG_DIR / "current-analysis.json"
SOC_ALERT_LLM_ANALYSIS_ACTIVE_DIR = SOC_ALERT_LLM_ANALYSIS_LOG_DIR / "active"
SOC_ALERT_LLM_ANALYSIS_RECORD_MAX_BYTES = 256 * 1024
SOC_ALERT_LLM_ANALYSIS_ACTIVE_LIMIT = 16
SOC_ALERT_LLM_ANALYSIS_LOG_INDEX = JsonlLogIndex(SOC_ALERT_LLM_ANALYSIS_LOG_FILE)
SOC_ANALYST_PROMPT_FILE = HOME / "n8n-local" / "config" / "soc_analyst_system_prompt.md"
SIEM_ENGINEER_PROMPT_FILE = HOME / "n8n-local" / "config" / "siem_engineer_system_prompt.md"
THREAT_HUNTER_PROMPT_FILE = HOME / "n8n-local" / "config" / "threat_hunter_system_prompt.md"
CYBER_THREAT_INTEL_PROMPT_FILE = (
    HOME / "n8n-local" / "config" / "cyber_threat_intel_system_prompt.md"
)
INCIDENT_RESPONDER_PROMPT_FILE = (
    HOME / "n8n-local" / "config" / "incident_responder_system_prompt.md"
)
SOC_ANALYST_SECOND_OPINION_PROMPT_FILE = (
    HOME / "n8n-local" / "config" / "soc_analyst_second_opinion_prompt.md"
)
SIEM_ENGINEER_SECOND_OPINION_PROMPT_FILE = (
    HOME / "n8n-local" / "config" / "siem_engineer_second_opinion_prompt.md"
)
THREAT_HUNTER_SECOND_OPINION_PROMPT_FILE = (
    HOME / "n8n-local" / "config" / "threat_hunter_second_opinion_prompt.md"
)
CYBER_THREAT_INTEL_SECOND_OPINION_PROMPT_FILE = (
    HOME / "n8n-local" / "config" / "cyber_threat_intel_second_opinion_prompt.md"
)
INCIDENT_RESPONDER_SECOND_OPINION_PROMPT_FILE = (
    HOME / "n8n-local" / "config" / "incident_responder_second_opinion_prompt.md"
)
SOC_SETTINGS_PROMPT_FILES = {
    "/api/soc-settings/analyst-prompt": (
        "SOC Analyst", SOC_ANALYST_PROMPT_FILE
    ),
    "/api/soc-settings/analyst-second-opinion-prompt": (
        "SOC Analyst second-opinion", SOC_ANALYST_SECOND_OPINION_PROMPT_FILE
    ),
    "/api/soc-settings/siem-engineer-prompt": (
        "SIEM Engineer", SIEM_ENGINEER_PROMPT_FILE
    ),
    "/api/soc-settings/siem-engineer-second-opinion-prompt": (
        "SIEM Engineer second-opinion", SIEM_ENGINEER_SECOND_OPINION_PROMPT_FILE
    ),
    "/api/soc-settings/threat-hunter-prompt": (
        "Threat Hunter", THREAT_HUNTER_PROMPT_FILE
    ),
    "/api/soc-settings/threat-hunter-second-opinion-prompt": (
        "Threat Hunter second-opinion", THREAT_HUNTER_SECOND_OPINION_PROMPT_FILE
    ),
    "/api/soc-settings/cyber-threat-intel-prompt": (
        "Cyber Threat Intel", CYBER_THREAT_INTEL_PROMPT_FILE
    ),
    "/api/soc-settings/cyber-threat-intel-second-opinion-prompt": (
        "Cyber Threat Intel second-opinion",
        CYBER_THREAT_INTEL_SECOND_OPINION_PROMPT_FILE,
    ),
    "/api/soc-settings/incident-responder-prompt": (
        "Incident Responder", INCIDENT_RESPONDER_PROMPT_FILE
    ),
    "/api/soc-settings/incident-responder-second-opinion-prompt": (
        "Incident Responder second-opinion",
        INCIDENT_RESPONDER_SECOND_OPINION_PROMPT_FILE,
    ),
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
SOC_ALERT_AI_ELIGIBLE_FILTER_STATUSES = {
    "accepted", "escalated", "unknown", "suppressed"
}
SOC_ALERT_TEST_PREFIXES = (
    "phase", "config-", "internal-test-", "sqlite-", "policy-", "codex-"
)
SOC_ALERT_ARTIFACT_CACHE_TTL_SECONDS = 5.0
SOC_ALERT_ARTIFACT_CACHE = ArtifactCache(SOC_ALERT_ARTIFACT_CACHE_TTL_SECONDS)
SOC_ALERT_RESPONSE_CACHE = ResponseCache(1.0)
SOC_ALERT_EVENTS_CACHE = ResponseCache(4.0, max_entries=2, lock_stripes=1)
OLLAMA_MODEL_COMPATIBILITY_CACHE = ResponseCache(
    300.0, max_entries=128, lock_stripes=16
)
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
RESOURCE_LIBRARY_BUILDER = (
    HOME / ".hermes" / "scripts" / "build_pdf_library_dashboard.py"
)
RESOURCE_LIBRARY_SYNC = HOME / ".hermes" / "scripts" / "sync_report_portal.py"
RESOURCE_LIBRARY_MUTATION_WORKER = (
    HOME / ".hermes" / "scripts" / "process_resource_library_removals.py"
)
RESOURCE_LIBRARY_REMOVAL_QUEUE = (
    HOME / "report_portal" / ".resource_removal_queue" / "requests.jsonl"
)
RESOURCE_LIBRARY_METADATA_FILE = (
    HOME / "report_portal" / "resource_library_metadata.json"
)
RESOURCE_LIBRARY_ACTION_STATUS_DIR = (
    HOME / "report_portal" / ".resource_removal_queue" / "status"
)
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
    "PATH": (
        f"/opt/homebrew/bin:{HOME / '.hermes' / 'hermes-agent' / 'venv' / 'bin'}:"
        "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    ),
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
        "command": [
            "/bin/bash", "-lc",
            "/opt/homebrew/bin/brew update && /opt/homebrew/bin/brew upgrade",
        ],
        "accent": "#f8c76a",
    },
    "macos-update": {
        "label": "macOS software updates",
        "summary": (
            "Runs softwareupdate --install --all --agree-to-license. Some macOS "
            "updates may still require admin authorization or a restart."
        ),
        "command": [
            "/usr/sbin/softwareupdate", "--install", "--all", "--agree-to-license"
        ],
        "accent": "#a78bfa",
    },
    "reboot": {
        "label": "Reboot system",
        "summary": (
            "Reboots the Mac with passwordless sudo after typed confirmation. "
            "Requires the LAN Portal sudoers drop-in that allows only the exact "
            "reboot command."
        ),
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
ISO_DATE_TIME_SEPARATOR_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2})(?:T|\s+)(?=\d{2}:\d{2}:\d{2})"
)

__all__ = tuple(
    name for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
)
