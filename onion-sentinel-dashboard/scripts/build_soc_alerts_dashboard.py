#!/usr/bin/env python3
"""Build the SOC Alerts webpage for the LAN Portal from alert-store SQLite.

Primary source:
- ~/n8n-local/alert_store_data/alerts.sqlite3

Markdown corpus:
- ~/Documents/SOC Alerts

Output:
- ~/SOC Alerts Web/index.html

Troubleshooting notes:
- If row counts look too low, inspect the SQLite alerts table first.
- If a row has no rich Markdown detail, check whether n8n wrote a matching
  report with the same alert_id under ~/Documents/SOC Alerts.
- This is still a static page generator; very large alert volumes should move
  to an API-backed paginated dashboard.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import html
import json
import math
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from dashboard_metric_components import (  # noqa: E402
    render_active_alerts_metric,
    render_ai_activity_metric as render_ai_activity_metric_card,
    render_alert_status_metric,
    render_latest_network_metric,
    render_size_metric as render_size_metric_card,
)

HOME = Path.home()
SOURCE_DIR = HOME / 'Documents' / 'SOC Alerts'
ALT_SOURCE_DIR = HOME / 'n8n-local' / 'soc-alerts'
AI_PROMPT_DIR = HOME / 'n8n-local' / 'soc-alerts' / 'ai-prompts'
AI_ANALYSIS_DIR = HOME / 'n8n-local' / 'soc-alerts' / 'ai-analysis'
PCAP_ANALYSIS_DIR = HOME / 'n8n-local' / 'soc-alerts' / 'pcap-analysis'
PCAP_ARTIFACT_DIR = HOME / 'n8n-local' / 'pcap-evidence' / 'artifacts'
AGENT_MEMORY_DIR = HOME / 'n8n-local' / 'soc-alerts' / 'agent-memory'
OUT_DIR = HOME / 'SOC Alerts Web'
INDEX = OUT_DIR / 'index.html'
DETAIL_DIR = OUT_DIR / 'details'
STATUS_JSON = OUT_DIR / 'soc-alerts-status.json'
N8N_BEACON_JSON = OUT_DIR / 'n8n-beacon.json'
N8N_BEACON_HISTORY_JSON = OUT_DIR / 'n8n-beacon-history.json'
DB_PATH = HOME / 'n8n-local' / 'alert_store_data' / 'alerts.sqlite3'
DB_BEACON_JSON = HOME / 'n8n-local' / 'alert_store_data' / 'n8n-beacon.json'
DB_BEACON_HISTORY_JSON = HOME / 'n8n-local' / 'alert_store_data' / 'n8n-beacon-history.json'
SOC_ANALYST_PROMPT_FILE = HOME / 'n8n-local' / 'config' / 'soc_analyst_system_prompt.md'
SIEM_ENGINEER_PROMPT_FILE = HOME / 'n8n-local' / 'config' / 'siem_engineer_system_prompt.md'
THREAT_HUNTER_PROMPT_FILE = HOME / 'n8n-local' / 'config' / 'threat_hunter_system_prompt.md'
CYBER_THREAT_INTEL_PROMPT_FILE = HOME / 'n8n-local' / 'config' / 'cyber_threat_intel_system_prompt.md'
INCIDENT_RESPONDER_PROMPT_FILE = HOME / 'n8n-local' / 'config' / 'incident_responder_system_prompt.md'
SOC_ANALYST_MEMORY_FILE = AGENT_MEMORY_DIR / 'soc-analyst-memory.md'
INCIDENT_RESPONDER_MEMORY_FILE = AGENT_MEMORY_DIR / 'incident-responder-memory.md'
SIEM_ENGINEER_MEMORY_FILE = AGENT_MEMORY_DIR / 'siem-engineer-memory.md'
THREAT_HUNTER_MEMORY_FILE = AGENT_MEMORY_DIR / 'threat-hunter-memory.md'
CYBER_THREAT_INTEL_MEMORY_FILE = AGENT_MEMORY_DIR / 'cyber-threat-intel-memory.md'
SHARED_AGENT_MEMORY_FILE = AGENT_MEMORY_DIR / 'shared-agent-memory.md'
SOC_AI_SETTINGS_FILE = HOME / 'n8n-local' / 'config' / 'ai_model_settings.json'
ASSET_SOURCE_DIRS = (
    Path(__file__).resolve().parent.parent / 'assets',
    HOME / '.hermes' / 'assets',
)
SUPPORTED_SUFFIXES = {'.md', '.markdown'}
MARKDOWN_SOURCES = (SOURCE_DIR, ALT_SOURCE_DIR)
PAGE_DEFS = [
    ('home', 'home.html', 'Home', 'Executive SOC metrics and trends'),
    ('alerts', 'index.html', 'SOC Alerts', 'AI-powered triage and investigation'),
    ('system_health', 'system-health.html', 'System Health', 'n8n relay beacon history and gaps'),
    ('investigations', 'investigations.html', 'Incident Responder', 'Incident response case work and analyst follow-up'),
    ('cyber_threat_intel', 'cyber-threat-intel.html', 'Cyber Threat Intel', 'Threat intelligence briefs, indicators, and enrichment context'),
    ('siem_engineering', 'siem-engineering.html', 'SIEM Engineer', 'Tuning recommendations and detection engineering workspace'),
    ('threat_hunter', 'threat-hunter.html', 'Threat Hunter', 'Hunting workspace for suspicious patterns, pivots, and investigation leads'),
    ('reports', 'reports.html', 'Reports', 'Markdown reports and daily rollups'),
    ('playbooks', 'playbooks.html', 'Playbooks', 'Response checklists and investigation paths'),
    ('automations', 'automations.html', 'Automations', 'n8n workflow and relay automation status'),
    ('sources', 'sources.html', 'Sources', 'Security Onion, relay, SQLite, and AI data sources'),
    ('settings', 'settings.html', 'Settings', 'Dashboard and SOC workflow configuration'),
    ('flow', 'flow.html', 'Flow', 'Autonomous SIEM alert enrichment flow map'),
]
PAGE_BY_KEY = {key: {'filename': filename, 'title': title, 'subtitle': subtitle} for key, filename, title, subtitle in PAGE_DEFS}
ENRICHMENT_FLOW_SERVICES = [
    {'name': 'AbuseIPDB', 'asset': 'assets/brand/enrichment/abuseipdb.ico', 'scope': 'IP reputation', 'note': 'key gated'},
    {'name': 'GreyNoise', 'asset': 'assets/brand/enrichment/greynoise.ico', 'scope': 'scanner context', 'note': 'key gated'},
    {'name': 'Shodan InternetDB', 'asset': 'assets/brand/enrichment/shodan.ico', 'scope': 'open ports', 'note': 'no key'},
    {'name': 'OTX', 'asset': 'assets/brand/enrichment/otx.ico', 'scope': 'pulses + IOCs', 'note': 'key gated'},
    {'name': 'URLhaus', 'asset': 'assets/brand/enrichment/urlhaus.ico', 'scope': 'malware URLs', 'note': 'key gated'},
    {'name': 'VirusTotal', 'asset': 'assets/brand/enrichment/virustotal.ico', 'scope': 'selective reputation', 'note': '4/min'},
    {'name': 'urlscan.io', 'asset': 'assets/brand/enrichment/urlscan.ico', 'scope': 'URL search', 'note': 'key gated'},
    {'name': 'Google Safe Browsing', 'asset': 'assets/brand/enrichment/google.ico', 'scope': 'unsafe URLs', 'note': 'key gated'},
    {'name': 'PhishTank', 'asset': 'assets/brand/enrichment/phishtank.ico', 'scope': 'phishing URLs', 'note': 'key gated'},
    {'name': 'MalwareBazaar', 'asset': 'assets/brand/enrichment/malwarebazaar.ico', 'scope': 'file hashes', 'note': 'key gated'},
    {'name': 'ThreatFox', 'asset': 'assets/brand/enrichment/threatfox.ico', 'scope': 'C2 IOCs', 'note': 'key gated'},
    {'name': 'Shodan', 'asset': 'assets/brand/enrichment/shodan.ico', 'scope': 'host exposure', 'note': 'key gated'},
    {'name': 'Censys', 'asset': '', 'fallback': 'C', 'scope': 'exposure search', 'note': 'key gated'},
    {'name': 'CISA KEV', 'asset': 'assets/brand/enrichment/cisa.ico', 'scope': 'known exploited CVEs', 'note': 'no key'},
    {'name': 'EPSS', 'asset': 'assets/brand/enrichment/first.ico', 'scope': 'exploit probability', 'note': 'no key'},
    {'name': 'NVD', 'asset': 'assets/brand/enrichment/nvd.ico', 'scope': 'CVE metadata', 'note': 'optional key'},
]
GROUP_FALLBACK_VALUES = {
    'triage_level': 'unscored',
    'rule_name': 'unknown-rule',
    'source_ip': 'unknown-source',
    'destination_ip': 'unknown-destination',
    'filter_status': 'accepted',
}


def load_analyst_group_statuses() -> dict[str, dict[str, object]]:
    """Return analyst-controlled group states from SQLite without creating tables."""
    if not DB_PATH.exists():
        return {}
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'analyst_alert_group_state'"
        ).fetchone()
        if not exists:
            return {}
        rows = conn.execute(
            """
            SELECT group_id, status, repeat_count
            FROM analyst_alert_group_state
            WHERE status IN ('acknowledged', 'suppressed')
            """
        ).fetchall()
        return {
            str(row['group_id']): {
                'status': str(row['status'] or 'open'),
                'repeat_count': safe_int(row['repeat_count']),
            }
            for row in rows
        }
    except sqlite3.Error:
        return {}
    finally:
        conn.close()
AI_ELIGIBLE_FILTER_STATUSES = {'accepted', 'escalated', 'unknown', 'suppressed'}
TEST_ALERT_PREFIXES = ('phase', 'config-', 'internal-test-', 'sqlite-', 'policy-', 'codex-')
ISO_DATE_TIME_SEPARATOR_RE = re.compile(r'(\d{4}-\d{2}-\d{2})(?:T|\s+)(?=\d{2}:\d{2}:\d{2})')
ISO_TIMESTAMP_RE = re.compile(
    r'\b\d{4}-\d{2}-\d{2}(?:T|\s+)\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b'
)
DEFAULT_SOC_ANALYST_PROMPT = """You are a careful SOC analyst. Use only the supplied evidence.

Your job is to analyze Security Onion alerts for an analyst working a home/lab SOC environment. Be precise, skeptical, and operationally useful.

Rules:
- Return one valid JSON object and no prose outside JSON.
- Use only the provided alert, enrichment, grouped-alert, and rollup evidence.
- Do not invent packet contents, hostnames, users, process names, commands, malware families, or business context.
- Separate facts from hypotheses.
- If evidence is missing, explicitly identify the gap.
- Consider duplicate count, first/last seen timing, and repeated-alert patterns when judging urgency.
- Recommend concrete next investigative actions.
- Recommend tuning only when the evidence supports suppression, dropping, score changes, or more data collection.
- Prefer local/private analysis. Recommend hosted second opinion only when severity, uncertainty, or impact justifies it."""

DEFAULT_SIEM_ENGINEER_PROMPT = """You are a careful SIEM engineer. Use only the supplied Onion Sentinel evidence.

Your job is to review analyzed Security Onion detections, enrichment, analyst notes, acknowledgments, suppressions, duplicate timelines, and AI analysis artifacts, then recommend safe SIEM engineering improvements.

Rules:
- Return one valid JSON object and no prose outside JSON.
- Run only after all eligible alerts/detections are already analyzed.
- Treat acknowledgments and suppressions as analyst signals, not proof that activity is safe.
- Recommend tuning only when the evidence supports it and the condition is specific enough to avoid hiding unrelated threats.
- Separate current-rule tuning from new rule or detection creation.
- Prefer scoped conditions: rule name, source IP, destination IP, destination port, direction, suppression key, threshold, time window, asset role, and known-benign reason.
- Include validation steps and rollback guidance for every tuning recommendation.
- If evidence is insufficient, recommend data collection instead of tuning.
- Do not invent hostnames, users, packet contents, tools, malware names, or business context."""

DEFAULT_THREAT_HUNTER_PROMPT = """You are a senior threat hunt analyst. Use only the supplied Onion Sentinel evidence unless an enrichment source is explicitly provided.

You are an expert in Security Onion, Elastic Kibana KQL syntax, OQL Security Union Hunt syntax, and OSQuery syntax. Your job is to turn alert patterns, enrichments, acknowledgments, suppressions, analyst notes, AI analysis, duplicate timelines, and evidence gaps into precise threat-hunting hypotheses and safe hunt plans.

Rules:
- Return one valid JSON object and no prose outside JSON.
- Separate facts, assumptions, hypotheses, and required validation.
- Prefer hunts that an analyst can run quickly in Security Onion, Elastic/Kibana, and host telemetry.
- Include KQL, OQL, and OSQuery query examples when the available evidence supports them.
- Scope queries tightly by rule name, source IP, destination IP, destination port, event dataset, time window, and observed pattern.
- Do not invent hostnames, usernames, process names, packet contents, malware families, or business context.
- If evidence is insufficient, propose a data-collection hunt instead of claiming compromise.
- Include expected benign explanations, escalation criteria, and what evidence would close the hunt."""

DEFAULT_CYBER_THREAT_INTEL_PROMPT = """You are a senior cyber threat intelligence analyst. Use only the supplied Onion Sentinel evidence unless an enrichment source is explicitly provided.

Your job is to turn Security Onion detections, alert timelines, enrichments, analyst notes, acknowledgments, suppressions, AI analysis, and related hunt/engineering context into concise threat intelligence useful to SOC analysts, incident responders, threat hunters, and SIEM engineers.

Rules:
- Return one valid JSON object and no prose outside JSON.
- Separate observed facts, analytic judgments, confidence, assumptions, and intelligence gaps.
- Use Cyber Threat Intel memory and shared Cyber Security Agent memory when supplied, but treat memory as context, not proof.
- Identify relevant indicators, behaviors, infrastructure patterns, ATT&CK-style tactics/techniques when evidence supports them, and likely benign explanations.
- Recommend enrichment pivots such as reputation, ASN, passive DNS, WHOIS/RDAP, certificate, JA3/JA4, URL/domain, malware sandbox, and internal asset context, but do not claim results that were not supplied.
- Produce analyst-ready intelligence briefs with source limits, confidence, watchlist ideas, and follow-up questions.
- Do not invent hostnames, users, packet contents, malware families, threat actor names, geolocation, attribution, or business context.
- If evidence is insufficient, say what additional enrichment would improve the assessment."""

DEFAULT_INCIDENT_RESPONDER_PROMPT = """You are a senior cyber security incident responder. Use only the supplied Onion Sentinel evidence unless an enrichment source is explicitly provided.

Your job is to conduct incident response planning and case execution guidance for Security Onion detections, alert timelines, enrichments, analyst notes, acknowledgments, suppressions, AI analysis, and related host/network context. You may recommend external tooling, including custom host artifact collection scripts run from a dedicated incident response host with access to additional hosts, but do not assume that integration is available until it is explicitly configured.

Rules:
- Return one valid JSON object and no prose outside JSON.
- Separate confirmed facts, assumptions, hypotheses, impact, containment needs, and evidence gaps.
- Prioritize responder safety: preserve evidence, avoid destructive actions, and call out actions that could disrupt production systems.
- Recommend host artifact collection only when justified by the evidence, and specify the exact collection goal, target host, expected artifacts, and privacy/scope limits.
- Treat acknowledgments and suppressions as analyst workflow signals, not proof that an alert is benign.
- Do not invent hostnames, usernames, process names, packet contents, malware families, credentials, or business context.
- If dedicated incident response host access is required, mark the action as pending integration rather than executable.
- Include escalation criteria, containment options, eradication/recovery considerations, and post-incident tuning or hunt follow-up."""


def normalize_iso_display_text(value: object) -> str:
    """Display timestamps as local ISO 8601 with two spaces instead of `T`."""
    def replace_timestamp(match: re.Match[str]) -> str:
        parsed = parse_iso_datetime(match.group(0))
        return format_project_timestamp(parsed) if parsed else ISO_DATE_TIME_SEPARATOR_RE.sub(r'\1  ', match.group(0))

    return ISO_TIMESTAMP_RE.sub(replace_timestamp, str(value))


def load_soc_analyst_prompt() -> str:
    """Read the editable SOC Analyst system prompt for the Settings page."""
    try:
        prompt = SOC_ANALYST_PROMPT_FILE.read_text(encoding='utf-8').strip()
        if prompt:
            return prompt
    except Exception:
        pass
    return DEFAULT_SOC_ANALYST_PROMPT


def load_siem_engineer_prompt() -> str:
    """Read the editable SIEM Engineer system prompt for the Settings page."""
    try:
        prompt = SIEM_ENGINEER_PROMPT_FILE.read_text(encoding='utf-8').strip()
        if prompt:
            return prompt
    except Exception:
        pass
    return DEFAULT_SIEM_ENGINEER_PROMPT


def load_threat_hunter_prompt() -> str:
    """Read the editable Threat Hunter system prompt for the Settings page."""
    try:
        prompt = THREAT_HUNTER_PROMPT_FILE.read_text(encoding='utf-8').strip()
        if prompt:
            return prompt
    except Exception:
        pass
    return DEFAULT_THREAT_HUNTER_PROMPT


def load_cyber_threat_intel_prompt() -> str:
    """Read the editable Cyber Threat Intel Analyst system prompt for the Settings page."""
    try:
        prompt = CYBER_THREAT_INTEL_PROMPT_FILE.read_text(encoding='utf-8').strip()
        if prompt:
            return prompt
    except Exception:
        pass
    return DEFAULT_CYBER_THREAT_INTEL_PROMPT


def load_incident_responder_prompt() -> str:
    """Read the editable Incident Responder system prompt for the Settings page."""
    try:
        prompt = INCIDENT_RESPONDER_PROMPT_FILE.read_text(encoding='utf-8').strip()
        if prompt:
            return prompt
    except Exception:
        pass
    return DEFAULT_INCIDENT_RESPONDER_PROMPT


def display_path(path: Path) -> str:
    """Return a compact operator-facing path with $HOME shown as ~."""
    return str(path).replace(str(HOME), '~')


def default_soc_ai_settings() -> dict[str, str]:
    """Return safe model-routing defaults for the Settings page."""
    return {
        'mode': 'ollama',
        'ollama_model': os.environ.get('SOC_AI_MODEL', '').strip() or 'devstral:latest',
        'ollama_url': os.environ.get('OLLAMA_URL', '').strip() or 'http://127.0.0.1:11434',
        'cloud_provider': 'gpt-cli',
        'cloud_model': '',
        'cloud_command': '',
        'hybrid_policy': 'cloud_for_critical_high_or_recommended',
    }


def load_soc_ai_settings() -> dict[str, str]:
    """Read persisted AI model-routing settings for display."""
    settings = default_soc_ai_settings()
    try:
        data = json.loads(SOC_AI_SETTINGS_FILE.read_text(encoding='utf-8'))
    except Exception:
        data = {}
    if isinstance(data, dict):
        for key in settings:
            if key in data and data[key] is not None:
                settings[key] = str(data[key]).strip()
    if settings['mode'] not in {'ollama', 'cloud', 'hybrid'}:
        settings['mode'] = 'ollama'
    if settings['hybrid_policy'] not in {'cloud_for_critical_high_or_recommended', 'cloud_when_recommended_only'}:
        settings['hybrid_policy'] = 'cloud_for_critical_high_or_recommended'
    settings['ollama_model'] = settings['ollama_model'] or 'devstral:latest'
    settings['ollama_url'] = settings['ollama_url'] or 'http://127.0.0.1:11434'
    return settings


def list_ollama_models() -> list[str]:
    """Return locally available Ollama model names from `ollama ls`."""
    commands = [
        ['/opt/homebrew/bin/ollama', 'ls'],
        ['/usr/local/bin/ollama', 'ls'],
        ['ollama', 'ls'],
    ]
    output = ''
    for command in commands:
        try:
            proc = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        except Exception:
            continue
        if proc.returncode == 0 and proc.stdout.strip():
            output = proc.stdout
            break
    models: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith('name'):
            continue
        name = stripped.split()[0].strip()
        if name and name not in models:
            models.append(name)
    return models


def ollama_model_options(selected_model: str) -> str:
    models = list_ollama_models()
    selected_model = selected_model.strip() or 'devstral:latest'
    if selected_model and selected_model not in models:
        models.insert(0, selected_model)
    if not models:
        models = [selected_model]
    return '\n'.join(
        f'<option value="{html.escape(model)}" {"selected" if model == selected_model else ""}>{html.escape(model)}</option>'
        for model in models
    )


def current_local_ai_model() -> str:
    """Return the local Ollama model most recently used for alert analysis."""
    env_model = os.environ.get('SOC_AI_MODEL', '').strip()
    candidates: list[str] = []
    settings = load_soc_ai_settings()
    candidates.append(settings.get('ollama_model', '').strip())
    try:
        for path in sorted(AI_ANALYSIS_DIR.glob('*.json'), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                data = json.loads(path.read_text(encoding='utf-8'))
            except Exception:
                continue
            response = data.get('response') if isinstance(data.get('response'), dict) else {}
            for value in (
                data.get('analysis_model'),
                data.get('_analysis_model'),
                data.get('model'),
                response.get('_analysis_model'),
            ):
                if value:
                    candidates.append(str(value).strip())
            if candidates:
                break
    except Exception:
        pass
    candidates.extend([
        env_model,
        'devstral:latest',
    ])
    return next((candidate for candidate in candidates if candidate), 'devstral:latest')


def count_ai_analysis_artifacts(suffix: str) -> int:
    """Count local AI output artifacts by extension for Flow page metrics."""
    if not AI_ANALYSIS_DIR.exists():
        return 0
    return sum(1 for path in AI_ANALYSIS_DIR.glob(f'*-local-ai-analysis{suffix}') if path.is_file())


def telegram_sent_counts() -> dict[str, int]:
    """Read actual Telegram notification send counts from alert-store SQLite."""
    counts = {'critical': 0, 'high': 0}
    if not DB_PATH.exists():
        return counts
    try:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                """
                SELECT lower(coalesce(triage_level, 'unknown')) AS level,
                       sum(coalesce(sent_count, 1)) AS sent
                FROM notification_log
                WHERE channel = 'telegram'
                GROUP BY 1
                """
            ).fetchall()
    except sqlite3.Error:
        return counts
    for level, sent in rows:
        if level in counts:
            counts[level] = safe_int(sent)
    return counts


@dataclass
class AlertReport:
    # This view model feeds the existing static UI. It can represent either a
    # DB row with generated detail text or a DB row with a matching Markdown
    # report attached.
    title: str
    source: Path
    rel_source: str
    mtime: float
    size: int
    digest: str
    rendered_html: str
    summary: str
    criticality: str
    criticality_rank: int
    alert_source: str
    filter_status: str
    source_ip: str
    source_port: str
    destination_ip: str
    destination_port: str
    source_endpoint: str
    destination_endpoint: str
    rule_id: str
    rule_name: str
    raw_alert_count: int
    total_seen_count: int
    repeat_count: int
    first_seen: str
    last_seen: str
    alert_group_key: str
    alert_ts: float
    ai_status_key: str
    ai_status_label: str
    ai_status_detail: str
    enrichment_status_key: str
    enrichment_status_label: str
    enrichment_status_detail: str
    enrichment_record_count: int
    enrichment_skip_count: int
    enrichment_error_count: int
    pcap_status_key: str
    pcap_status_label: str
    pcap_status_detail: str
    tuning_recommendation: str
    tuning_reason: str
    recommended_tuning_actions: list[str]


def clean_title_from_markdown(text: str, path: Path) -> str:
    # Used only for legacy Markdown fallback and attached report titles.
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('#'):
            title = stripped.lstrip('#').strip()
            if title:
                return title[:180]
    return path.stem.replace('_', ' ').replace('-', ' ').strip().title() or path.name


CRITICALITY_ORDER = {
    'critical': 5,
    'high': 4,
    'medium': 3,
    'low': 2,
    'informational': 1,
    'info': 1,
}
CRITICALITY_LABELS = {
    'critical': 'Critical',
    'high': 'High',
    'medium': 'Medium',
    'low': 'Low',
    'informational': 'Informational',
    'info': 'Informational',
}


def detect_criticality(text: str, title: str, path: Path) -> tuple[str, int]:
    """Extract alert criticality from title/content/path with a stable severity order."""
    candidates = [title, path.name]
    candidates.extend(text.splitlines()[:40])
    joined = '\n'.join(candidates)
    patterns = [
        r'\[\s*(critical|high|medium|low|informational|info)\s*\]',
        r'\btriage\s+level\s*[:=]\s*["\']?(critical|high|medium|low|informational|info)\b',
        r'\bseverity\s*[:=]\s*["\']?(critical|high|medium|low|informational|info)\b',
        r'\bpriority\s*[:=]\s*["\']?(critical|high|medium|low|informational|info)\b',
    ]
    for pattern in patterns:
        match = re.search(pattern, joined, flags=re.IGNORECASE)
        if match:
            key = match.group(1).lower()
            return CRITICALITY_LABELS[key], CRITICALITY_ORDER[key]
    return 'Informational', CRITICALITY_ORDER['informational']


def criticality_class(label: str) -> str:
    return re.sub(r'[^a-z0-9]+', '-', label.lower()).strip('-') or 'informational'


def clean_endpoint_part(value: object | None) -> str:
    value = str(value or '').strip().strip('"\'')
    return value or '—'


def endpoint_label(ip: str | None, port: str | None) -> str:
    ip_label = clean_endpoint_part(ip)
    port_label = clean_endpoint_part(port)
    if ip_label != '—' and port_label != '—':
        return f'{ip_label}:{port_label}'
    if ip_label != '—':
        return f'{ip_label}:—'
    return '—'


def extract_network_endpoints(text: str) -> tuple[str, str, str, str]:
    """Extract source/destination IP and port from common Security Onion markdown report shapes."""
    traffic = re.search(
        r'\bTraffic:\*?\*?\s*([0-9a-fA-F:.]+):(\d+)\s*(?:->|→|-)\s*([0-9a-fA-F:.]+):(\d+)',
        text,
        flags=re.IGNORECASE,
    )
    if traffic:
        return traffic.group(1), traffic.group(2), traffic.group(3), traffic.group(4)

    source_obj = re.search(r'"source"\s*:\s*\{(?P<body>.*?)\n\s*\}', text, flags=re.IGNORECASE | re.DOTALL)
    dest_obj = re.search(r'"destination"\s*:\s*\{(?P<body>.*?)\n\s*\}', text, flags=re.IGNORECASE | re.DOTALL)

    def field(obj: re.Match[str] | None, name: str) -> str | None:
        if not obj:
            return None
        body = obj.group('body')
        m = re.search(rf'"{name}"\s*:\s*(?:"([^"]+)"|(\d+))', body, flags=re.IGNORECASE)
        return (m.group(1) or m.group(2)) if m else None

    src_ip_match = re.search(r'^source_ip:\s*["\']?([^"\'\n]+)', text, flags=re.IGNORECASE | re.MULTILINE)
    src_port_match = re.search(r'^source_port:\s*["\']?(\d+)', text, flags=re.IGNORECASE | re.MULTILINE)
    dst_ip_match = re.search(r'^(?:destination|dest)_ip:\s*["\']?([^"\'\n]+)', text, flags=re.IGNORECASE | re.MULTILINE)
    dst_port_match = re.search(r'^(?:destination|dest)_port:\s*["\']?(\d+)', text, flags=re.IGNORECASE | re.MULTILINE)

    src_ip = field(source_obj, 'ip') or (src_ip_match.group(1) if src_ip_match else None)
    src_port = field(source_obj, 'port') or (src_port_match.group(1) if src_port_match else None)
    dst_ip = field(dest_obj, 'ip') or (dst_ip_match.group(1) if dst_ip_match else None)
    dst_port = field(dest_obj, 'port') or (dst_port_match.group(1) if dst_port_match else None)
    return clean_endpoint_part(src_ip), clean_endpoint_part(src_port), clean_endpoint_part(dst_ip), clean_endpoint_part(dst_port)



def extract_rule_identity(text: str, title: str) -> tuple[str, str]:
    """Extract a stable rule identity from Security Onion report markdown/raw JSON."""
    rule_id_match = re.search(r'"rule_id"\s*:\s*"?([^",\n]+)"?', text, flags=re.IGNORECASE)
    rule_name_match = re.search(r'"rule_name"\s*:\s*"([^"]+)"', text, flags=re.IGNORECASE)
    if not rule_name_match:
        rule_name_match = re.search(r'\|\s*Rule name\s*\|\s*([^|]+?)\s*\|', text, flags=re.IGNORECASE)
    rule_id = clean_endpoint_part(rule_id_match.group(1) if rule_id_match else '')
    rule_name = clean_endpoint_part(rule_name_match.group(1) if rule_name_match else title)
    return rule_id, rule_name


def parse_iso_timestamp(value: str | None) -> float | None:
    parsed = parse_iso_datetime(value)
    return parsed.timestamp() if parsed else None


def parse_iso_datetime(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    cleaned = value.strip().strip('"\'')
    if not cleaned:
        return None
    try:
        parseable = ISO_DATE_TIME_SEPARATOR_RE.sub(r'\1T', cleaned).replace('Z', '+00:00')
        parsed = dt.datetime.fromisoformat(parseable)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def format_project_timestamp(value: dt.datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    local_value = value.astimezone()
    timespec = 'milliseconds' if local_value.microsecond else 'seconds'
    return local_value.isoformat(timespec=timespec).replace('T', '  ')


def extract_alert_timestamp(text: str, fallback_ts: float) -> float:
    """Use event time when available; fall back to file mtime."""
    patterns = [
        r'"timestamp"\s*:\s*"([^"]+)"',
        r'\|\s*Timestamp\s*\|\s*([^|]+?)\s*\|',
        r'^generated_at:\s*([^\n]+)',
        r'^-\s*\*\*Generated:\*\*\s*([^\n]+)',
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
        ts = parse_iso_timestamp(match.group(1)) if match else None
        if ts is not None:
            return ts
    return fallback_ts


def summarize_markdown(text: str, max_len: int = 220) -> str:
    lines = []
    in_code = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith('```'):
            in_code = not in_code
            continue
        if in_code or not line or line.startswith('#'):
            continue
        if re.match(r'^[-*_]{3,}$', line):
            continue
        line = re.sub(r'[`*_>#\[\]()]+', ' ', line)
        line = re.sub(r'\s+', ' ', line).strip()
        line = normalize_iso_display_text(line)
        if line:
            lines.append(line)
        if sum(len(x) for x in lines) > max_len:
            break
    summary = normalize_iso_display_text(' '.join(lines).strip())
    return (summary[:max_len - 1] + '…') if len(summary) > max_len else (summary or 'No summary text available yet.')


def compact_text(text: str, max_len: int = 150) -> str:
    text = normalize_iso_display_text(re.sub(r'\s+', ' ', str(text or '')).strip())
    if not text:
        return ''
    sentence = re.split(r'(?<=[.!?])\s+', text, maxsplit=1)[0].strip()
    clipped = sentence if sentence else text
    return (clipped[:max_len - 1].rstrip() + '…') if len(clipped) > max_len else clipped


def inline_markdown(text: str) -> str:
    # Minimal Markdown rendering keeps this script dependency-free on macOS.
    # It is intentionally small; complex Markdown should stay readable as text.
    escaped = html.escape(text)
    escaped = re.sub(r'`([^`]+)`', r'<code>\1</code>', escaped)
    escaped = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', escaped)
    escaped = re.sub(r'\*([^*]+)\*', r'<em>\1</em>', escaped)
    escaped = re.sub(
        r'\[([^\]]+)\]\((https?://[^\s)]+)\)',
        lambda m: f'<a href="{html.escape(m.group(2), quote=True)}" target="_blank" rel="noopener">{m.group(1)}</a>',
        escaped,
    )
    return escaped


def is_table_separator(line: str) -> bool:
    cells = [cell.strip() for cell in line.strip().strip('|').split('|')]
    return bool(cells) and all(re.fullmatch(r':?-{3,}:?', cell or '') for cell in cells)


def render_table(lines: list[str]) -> str:
    rows = [[cell.strip() for cell in line.strip().strip('|').split('|')] for line in lines]
    if len(rows) < 2:
        return ''
    header = rows[0]
    body = rows[2:] if len(rows) > 2 and is_table_separator(lines[1]) else rows[1:]
    head_html = ''.join(f'<th>{inline_markdown(cell)}</th>' for cell in header)
    body_html = ''.join('<tr>' + ''.join(f'<td>{inline_markdown(cell)}</td>' for cell in row) + '</tr>' for row in body)
    normalized_header = [re.sub(r'[^a-z0-9]+', '_', cell.lower()).strip('_') for cell in header]
    table_classes = ['table-wrap']
    if normalized_header == ['source', 'indicator', 'type', 'verdict', 'confidence', 'tags', 'cached']:
        table_classes.append('public-enrichment-table')
    elif normalized_header == ['source', 'indicator', 'reason', 'limit_note']:
        table_classes.append('public-enrichment-table')
        table_classes.append('public-enrichment-skipped-table')
    return f'<div class="{" ".join(table_classes)}"><table><thead><tr>{head_html}</tr></thead><tbody>{body_html}</tbody></table></div>'


def markdown_to_html(text: str) -> str:
    # This renderer supports the subset of Markdown generated by n8n reports.
    # Keep changes conservative because the output is inserted directly into the
    # static LAN Portal page.
    blocks: list[str] = []
    paragraph: list[str] = []
    list_items: list[str] = []
    ordered_items: list[str] = []
    code_lines: list[str] = []
    table_lines: list[str] = []
    in_code = False
    collapsible_section_open = False
    collapsible_section_level = 0
    report_section_open = False
    report_section_level = 0

    def close_collapsible_section_if_open() -> None:
        nonlocal collapsible_section_open, collapsible_section_level
        if collapsible_section_open:
            blocks.append('</div></details>')
            collapsible_section_open = False
            collapsible_section_level = 0

    def close_report_section_if_open() -> None:
        nonlocal report_section_open, report_section_level
        if report_section_open:
            blocks.append('</section>')
            report_section_open = False
            report_section_level = 0

    def flush_paragraph() -> None:
        nonlocal paragraph
        if paragraph:
            blocks.append('<p>' + inline_markdown(' '.join(paragraph)) + '</p>')
            paragraph = []

    def flush_list() -> None:
        nonlocal list_items, ordered_items
        if list_items:
            blocks.append('<ul>' + ''.join(f'<li>{inline_markdown(item)}</li>' for item in list_items) + '</ul>')
            list_items = []
        if ordered_items:
            blocks.append('<ol>' + ''.join(f'<li>{inline_markdown(item)}</li>' for item in ordered_items) + '</ol>')
            ordered_items = []

    def flush_table() -> None:
        nonlocal table_lines
        if table_lines:
            rendered = render_table(table_lines)
            if rendered:
                blocks.append(rendered)
            else:
                blocks.extend('<p>' + inline_markdown(line) + '</p>' for line in table_lines)
            table_lines = []

    for raw in text.splitlines():
        line = raw.rstrip('\n')
        stripped = line.strip()
        if stripped.startswith('```'):
            flush_paragraph(); flush_list(); flush_table()
            if in_code:
                blocks.append('<pre><code>' + html.escape('\n'.join(code_lines)) + '</code></pre>')
                code_lines = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_lines.append(line)
            continue
        if not stripped:
            flush_paragraph(); flush_list(); flush_table()
            continue
        if '|' in stripped and stripped.count('|') >= 2:
            flush_paragraph(); flush_list()
            table_lines.append(stripped)
            continue
        flush_table()
        heading = re.match(r'^(#{1,6})\s+(.+)$', stripped)
        if heading:
            flush_paragraph(); flush_list()
            heading_level = len(heading.group(1))
            heading_text = heading.group(2).strip()
            if collapsible_section_open and heading_level <= collapsible_section_level:
                close_collapsible_section_if_open()
            if report_section_open and heading_level <= report_section_level:
                close_report_section_if_open()
            normalized_heading = re.sub(r'[^a-z0-9]+', ' ', re.sub(r'[`*_]+', '', heading_text.lower())).strip()
            collapsible_labels = {
                'raw alert': ('raw-alert-details', 'raw-alert-body', 'Raw Alert'),
                'complete alert json': ('raw-alert-details', 'raw-alert-body', 'Complete Alert JSON'),
                'complete ai response json': ('raw-alert-details', 'raw-alert-body', 'Complete AI Response JSON'),
            }
            if normalized_heading in collapsible_labels:
                details_class, body_class, summary_label = collapsible_labels[normalized_heading]
                collapsible_section_open = True
                collapsible_section_level = heading_level
                blocks.append(f'<details class="{details_class}"><summary>{summary_label}</summary><div class="{body_class}">')
                continue
            level = min(6, heading_level + 1)  # keep report h1 below page h1
            if heading_level <= 2:
                section_slug = re.sub(r'[^a-z0-9]+', '-', normalized_heading).strip('-') or 'section'
                report_section_open = True
                report_section_level = heading_level
                blocks.append(f'<section class="detail-report-section detail-section-{section_slug}">')
            blocks.append(f'<h{level}>{inline_markdown(heading_text)}</h{level}>')
            continue
        unordered = re.match(r'^[-*+]\s+(.+)$', stripped)
        if unordered:
            flush_paragraph()
            ordered_items = []
            list_items.append(unordered.group(1).strip())
            continue
        ordered = re.match(r'^\d+[.)]\s+(.+)$', stripped)
        if ordered:
            flush_paragraph()
            list_items = []
            ordered_items.append(ordered.group(1).strip())
            continue
        quote = re.match(r'^>\s*(.+)$', stripped)
        if quote:
            flush_paragraph(); flush_list()
            blocks.append(f'<blockquote>{inline_markdown(quote.group(1).strip())}</blockquote>')
            continue
        paragraph.append(stripped)

    flush_paragraph(); flush_list(); flush_table()
    if in_code and code_lines:
        blocks.append('<pre><code>' + html.escape('\n'.join(code_lines)) + '</code></pre>')
    close_collapsible_section_if_open()
    close_report_section_if_open()
    return '\n'.join(blocks) or '<p>No markdown content available.</p>'


def extract_markdown_alert_id(text: str) -> str | None:
    # Return the alert_id embedded in an n8n-generated Markdown report. This is
    # how SQLite rows are paired with their human/LLM report files.
    patterns = [
        r'^alert_id:\s*["\']?(.+?)["\']?\s*$',
        r'^-\s*\*\*Alert ID:\*\*\s*(.+?)\s*$',
        r'"alert_id"\s*:\s*"([^"]+)"',
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
        if not match:
            continue
        value = match.group(1).strip().strip('"\'')
        if value:
            return value
    return None


def load_markdown_reports_by_alert_id() -> dict[str, tuple[Path, str, os.stat_result]]:
    # Index Markdown reports so accepted alerts can still show rich LLM notes.
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    by_alert_id: dict[str, tuple[Path, str, os.stat_result]] = {}
    for source_dir in MARKDOWN_SOURCES:
        source_dir.mkdir(parents=True, exist_ok=True)
        for path in sorted(source_dir.rglob('*'), key=lambda p: str(p).lower()):
            if not path.is_file() or path.suffix.lower() not in SUPPORTED_SUFFIXES or path.name.startswith('.'):
                continue
            try:
                text = path.read_text(encoding='utf-8')
            except UnicodeDecodeError:
                text = path.read_text(encoding='utf-8', errors='replace')
            alert_id = extract_markdown_alert_id(text)
            if alert_id:
                by_alert_id[alert_id] = (path, text, path.stat())
    return by_alert_id


def load_ai_analysis_by_alert_id() -> dict[str, dict]:
    # Local AI analysis jobs write one JSON artifact per analyzed alert. Index
    # the newest artifact for each alert_id so the detail view can show exactly
    # which model evaluated the alert and what it concluded.
    by_alert_id: dict[str, dict] = {}
    if not AI_ANALYSIS_DIR.exists():
        return by_alert_id
    for path in sorted(AI_ANALYSIS_DIR.glob('*.json'), key=lambda p: p.stat().st_mtime):
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        alert_id = str(data.get('alert_id') or '').strip()
        if not alert_id:
            continue
        data['_analysis_path'] = str(path)
        data['_analysis_filename'] = path.name
        by_alert_id[alert_id] = data
    return by_alert_id


def load_ai_prompts_by_alert_id() -> dict[str, dict]:
    # Prompt packages are the queue input for local AI analysis. If a prompt
    # exists but no analysis artifact exists yet, the dashboard can show Queued.
    by_alert_id: dict[str, dict] = {}
    if not AI_PROMPT_DIR.exists():
        return by_alert_id
    for path in sorted(AI_PROMPT_DIR.glob('*.json'), key=lambda p: p.stat().st_mtime):
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        alert = data.get('alert') if isinstance(data.get('alert'), dict) else {}
        alert_id = str(alert.get('alert_id') or data.get('alert_id') or '').strip()
        if not alert_id:
            continue
        data['_prompt_path'] = str(path)
        data['_prompt_filename'] = path.name
        by_alert_id[alert_id] = data
    return by_alert_id


def running_ai_prompt_alert_ids(ai_prompts_by_alert_id: dict[str, dict]) -> set[str]:
    # The current runner is a short-lived local process. When it is active, its
    # command line includes the prompt package path, which lets the static page
    # label that alert as Analyzing during the next dashboard build.
    try:
        result = subprocess.run(['ps', 'axo', 'command='], check=False, capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return set()
    commands = result.stdout.splitlines()
    running: set[str] = set()
    for alert_id, prompt in ai_prompts_by_alert_id.items():
        prompt_path = str(prompt.get('_prompt_path') or '')
        if prompt_path and any('run-local-ai-analysis.py' in command and prompt_path in command for command in commands):
            running.add(alert_id)
    return running


def severity_label_from_row(row: sqlite3.Row) -> str:
    # Prefer deterministic triage level because it is what alert-store routed
    # on. Fall back to raw Security Onion severity if triage is absent.
    raw = (row['triage_level'] or row['severity_label'] or '').strip().lower()
    if raw in CRITICALITY_LABELS:
        return CRITICALITY_LABELS[raw]
    severity = row['severity']
    if severity == 1:
        return 'Critical'
    if severity == 2:
        return 'Medium'
    if severity == 3:
        return 'Low'
    return 'Informational'


def raw_alert_object(row: sqlite3.Row) -> dict:
    try:
        value = json.loads(row['alert_json'] or '{}')
        return value if isinstance(value, dict) else {}
    except json.JSONDecodeError:
        return {}


def json_object(value: object) -> dict:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value.strip():
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def row_value(row: sqlite3.Row | dict, key: str, default: object = None) -> object:
    if isinstance(row, dict):
        return row.get(key, default)
    try:
        return row[key]
    except (IndexError, KeyError):
        return default


def alert_group_key(row: sqlite3.Row) -> str:
    # Keep source port out of grouping because it can rotate per connection.
    if row['suppression_key']:
        return row['suppression_key']
    return (
        f"{row['triage_level'] or GROUP_FALLBACK_VALUES['triage_level']}|"
        f"{row['rule_name'] or GROUP_FALLBACK_VALUES['rule_name']}|"
        f"{row['source_ip'] or GROUP_FALLBACK_VALUES['source_ip']}|"
        f"{row['destination_ip'] or GROUP_FALLBACK_VALUES['destination_ip']}|"
        f"{row['filter_status'] or GROUP_FALLBACK_VALUES['filter_status']}"
    )


def safe_int(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def active_alert_reports(reports: list[AlertReport]) -> list[AlertReport]:
    """Return currently open grouped detections for the nav badge."""
    statuses = load_analyst_group_statuses()
    active = []
    for report in reports:
        meta = statuses.get(report.digest)
        status = str((meta or {}).get('status') or 'open').lower()
        repeat_count = safe_int((meta or {}).get('repeat_count'))
        if report.filter_status == 'suppressed':
            continue
        if status == 'suppressed':
            continue
        if status == 'acknowledged' and report.repeat_count <= repeat_count:
            continue
        active.append(report)
    return active


def active_alert_count(reports: list[AlertReport]) -> int:
    """Count currently open grouped detections for the nav badge."""
    return len(active_alert_reports(reports))


def active_alert_highest_severity_class(reports: list[AlertReport]) -> str:
    """Return the highest open grouped detection severity for the nav badge."""
    active = active_alert_reports(reports)
    if not active:
        return 'none'
    return criticality_class(max(active, key=lambda report: report.criticality_rank).criticality)


def nested_value(obj: dict, *keys: str) -> str | None:
    current = obj
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    if current is None:
        return None
    return str(current)


def nested_object(obj: dict, *keys: str) -> object | None:
    current: object = obj
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def markdown_cell(value: object, max_len: int = 420) -> str:
    # Keep generated Markdown tables valid even when alert fields contain pipes,
    # newlines, lists, or nested objects.
    if value is None or value == '' or value == [] or value == {}:
        return ''
    if isinstance(value, (dict, list)):
        rendered = json.dumps(value, sort_keys=True)
    else:
        rendered = str(value)
    rendered = re.sub(r'\s+', ' ', rendered).strip()
    rendered = rendered.replace('|', '\\|')
    return (rendered[:max_len - 1] + '…') if len(rendered) > max_len else rendered


def detail_table(title: str, rows: list[tuple[str, object]], max_len: int = 420) -> list[str]:
    visible_rows = [(label, markdown_cell(value, max_len)) for label, value in rows]
    visible_rows = [(label, value) for label, value in visible_rows if value]
    if not visible_rows:
        return []
    lines = [
        f'## {title}',
        '',
        '| Field | Value |',
        '| --- | --- |',
    ]
    lines.extend(f'| {label} | {value} |' for label, value in visible_rows)
    lines.append('')
    return lines


def raw_event_for_details(raw: dict) -> dict:
    # New exporter versions preserve selected original Security Onion fields
    # under security_onion.raw_event. Older rows can still render from the
    # normalized alert object.
    raw_event = nested_object(raw, 'security_onion', 'raw_event')
    return raw_event if isinstance(raw_event, dict) else raw


def complete_alert_json_markdown(raw: dict) -> str:
    alert_json = json.dumps(raw or {}, indent=2, sort_keys=True)
    return '\n'.join([
        '## Complete Alert JSON',
        '',
        'This block contains every alert field currently available to the dashboard from SQLite. Full-fidelity mode does not redact packet, payload, PCAP, or HTTP body fields.',
        '',
        '```json',
        alert_json,
        '```',
    ])


def raw_alert_markdown(raw: dict, fallback_json: str | None = None) -> str:
    alert_json = json.dumps(raw, indent=2, sort_keys=True) if raw else (fallback_json or '{}')
    return '\n'.join([
        '## Raw Alert',
        '',
        '```json',
        alert_json,
        '```',
    ])


def normalized_heading_text(line: str) -> tuple[int, str] | None:
    match = re.match(r'^(#{1,6})\s+(.+?)\s*$', line.strip())
    if not match:
        return None
    normalized = re.sub(r'[^a-z0-9]+', ' ', re.sub(r'[`*_]+', '', match.group(2).lower())).strip()
    return len(match.group(1)), normalized


def remove_markdown_sections(text: str, section_titles: set[str]) -> str:
    # Existing n8n Markdown can already contain large raw JSON sections. The
    # dashboard regenerates these from SQLite at the bottom so analysts always
    # get current, collapsible evidence without duplicated middle-of-report JSON.
    kept: list[str] = []
    skipping = False
    skip_level = 0
    for line in text.splitlines():
        heading = normalized_heading_text(line)
        if heading:
            level, title = heading
            if skipping and level <= skip_level:
                skipping = False
                skip_level = 0
            if not skipping and title in section_titles:
                skipping = True
                skip_level = level
                continue
        if not skipping:
            kept.append(line)
    return '\n'.join(kept).strip()


def bottom_evidence_markdown(raw: dict, fallback_json: str | None = None) -> str:
    return f'{complete_alert_json_markdown(raw)}\n\n{raw_alert_markdown(raw, fallback_json)}'


def markdown_bullets(value: object) -> str:
    if isinstance(value, list):
        items = [str(item).strip() for item in value if str(item).strip()]
        return '\n'.join(f'- {item}' for item in items) if items else '- n/a'
    if value in (None, '', [], {}):
        return '- n/a'
    return f'- {value}'


def candidate_alert_ids_for_row(row: sqlite3.Row | dict) -> list[str]:
    candidate_ids = [row['alert_id']]
    if isinstance(row, dict):
        candidate_ids.extend(row.get('member_alert_ids') or [])
    return [str(alert_id) for alert_id in candidate_ids if alert_id]


def is_test_alert_id(alert_id: str) -> bool:
    return alert_id.startswith(TEST_ALERT_PREFIXES)


def row_is_ai_backlog_eligible(row: sqlite3.Row | dict) -> tuple[bool, str]:
    candidate_ids = candidate_alert_ids_for_row(row)
    if candidate_ids and all(is_test_alert_id(alert_id) for alert_id in candidate_ids):
        return False, 'Test/validation alert is intentionally excluded from automatic local AI analysis'
    status = str(row['filter_status'] or 'accepted').strip().lower()
    if status not in AI_ELIGIBLE_FILTER_STATUSES:
        return False, f'Filter status {status or "blank"} is not eligible for automatic local AI analysis'
    return True, 'Queued for the scheduled local AI analysis worker'


def ai_analysis_for_row(row: sqlite3.Row | dict, ai_analysis_by_alert_id: dict[str, dict]) -> dict | None:
    candidate_ids = candidate_alert_ids_for_row(row)
    for alert_id in candidate_ids:
        analysis = ai_analysis_by_alert_id.get(alert_id)
        if analysis:
            return analysis
    return None


def ai_workflow_status_for_row(row: sqlite3.Row | dict, ai_analysis_by_alert_id: dict[str, dict], ai_prompts_by_alert_id: dict[str, dict], running_ai_alert_ids: set[str]) -> tuple[str, str, str]:
    candidate_ids = candidate_alert_ids_for_row(row)
    for alert_id in candidate_ids:
        if alert_id in running_ai_alert_ids:
            prompt = ai_prompts_by_alert_id.get(alert_id, {})
            return ('analyzing', 'Analyzing', prompt.get('_prompt_filename') or 'Local AI runner is active')
    for alert_id in candidate_ids:
        analysis = ai_analysis_by_alert_id.get(alert_id)
        if analysis:
            model = ''
            response = analysis.get('response') if isinstance(analysis.get('response'), dict) else {}
            if response:
                model = str(response.get('_analysis_model') or '')
            generated_at = analysis.get('generated_at') or 'complete'
            detail = normalize_iso_display_text(f'{model} at {generated_at}'.strip())
            return ('analyzed', 'Analyzed', detail)
    for alert_id in candidate_ids:
        prompt = ai_prompts_by_alert_id.get(alert_id)
        if prompt:
            generated_at = prompt.get('generated_at') or 'queued'
            return ('queued', 'Queued', normalize_iso_display_text(f'{prompt.get("_prompt_filename") or "prompt package"} at {generated_at}'))
    eligible, reason = row_is_ai_backlog_eligible(row)
    if not eligible:
        return ('not-queued', 'Skipped', reason)
    # The scheduled AI worker treats every eligible unique grouped alert as
    # backlog once it appears on the dashboard. A prompt package may not exist
    # yet because the worker generates prompts just-in-time.
    return ('queued', 'Queued', reason)


def ai_analysis_report_markdown(analysis: dict | None) -> str:
    if not analysis:
        return '\n'.join([
            '## AI Model Used',
            '',
            '| Field | Value |',
            '| --- | --- |',
            '| Analysis status | Not analyzed yet |',
            '| Model path | n/a |',
            '| Model | n/a |',
            '',
            '## AI Analysis Output',
            '',
            'No AI analysis artifact was found for this alert yet.',
        ])

    response = analysis.get('response') if isinstance(analysis.get('response'), dict) else {}
    model = response.get('_analysis_model') or analysis.get('analysis_model') or 'unknown'
    analysis_type = str(analysis.get('analysis_type') or '').strip().lower()
    model_path_labels = {
        'local-ai': 'Ollama local',
        'ollama': 'Ollama local',
        'frontier-cloud': 'Frontier cloud CLI',
        'hybrid': 'Hybrid local + cloud',
        'hybrid-local-only': 'Hybrid local-only',
    }
    model_path = model_path_labels.get(analysis_type, analysis.get('analysis_type') or 'unknown')
    generated_at = normalize_iso_display_text(analysis.get('generated_at') or 'unknown')
    prompt_package = analysis.get('prompt_package') or 'n/a'
    source_file = analysis.get('_analysis_filename') or 'n/a'
    source_path = analysis.get('_analysis_path') or 'n/a'
    lines = [
        '## AI Model Used',
        '',
        '| Field | Value |',
        '| --- | --- |',
        f'| Analysis status | Complete |',
        f'| Model path | {markdown_cell(model_path)} |',
        f'| Model | {markdown_cell(model)} |',
        f'| Generated at | {markdown_cell(generated_at)} |',
        f'| Analysis artifact | {markdown_cell(source_file)} |',
        f'| Prompt package | {markdown_cell(prompt_package)} |',
        f'| Artifact path | {markdown_cell(source_path, 700)} |',
        '',
        '## AI Analysis Output',
        '',
        '### Summary',
        '',
        str(response.get('summary') or 'n/a'),
        '',
        '### Likely Meaning',
        '',
        str(response.get('likely_meaning') or 'n/a'),
        '',
        '### Severity Reasoning',
        '',
        str(response.get('severity_reasoning') or 'n/a'),
        '',
        '### Alert Frequency Assessment',
        '',
        str(response.get('alert_frequency_assessment') or 'n/a'),
        '',
        '### PCAP Analysis Findings',
        '',
        markdown_bullets(response.get('pcap_analysis_findings')),
        '',
        '### False Positive Possibilities',
        '',
        markdown_bullets(response.get('false_positive_possibilities')),
        '',
        '### Recommended Next Steps',
        '',
        markdown_bullets(response.get('recommended_next_steps')),
        '',
        '### Evidence Used',
        '',
        markdown_bullets(response.get('evidence_used')),
        '',
        '### Evidence Gaps',
        '',
        markdown_bullets(response.get('evidence_gaps')),
        '',
        '### Tuning Recommendation',
        '',
        f"- **Recommendation:** {response.get('tuning_recommendation') or 'n/a'}",
        f"- **Reason:** {response.get('tuning_reason') or 'n/a'}",
        '',
        '#### Recommended Tuning Actions',
        '',
        markdown_bullets(response.get('recommended_tuning_actions')),
        '',
        '### Escalation',
        '',
        f"- **Confidence:** {response.get('confidence') or 'n/a'}",
        f"- **Escalation needed:** {response.get('escalation_needed') if 'escalation_needed' in response else 'n/a'}",
        f"- **Hosted second opinion recommended:** {response.get('hosted_second_opinion_recommended') if 'hosted_second_opinion_recommended' in response else 'n/a'}",
    ]
    return '\n'.join(lines)


def complete_ai_response_json_markdown(analysis: dict | None) -> str:
    if not analysis:
        return ''
    response = analysis.get('response') if isinstance(analysis.get('response'), dict) else {}
    if not response:
        return ''
    output_json = json.dumps(response, indent=2, sort_keys=True)
    return '\n'.join([
        '## Complete AI Response JSON',
        '',
        '```json',
        output_json,
        '```',
    ])


def timeline_timestamp(value: object) -> float | None:
    return parse_iso_timestamp(str(value)) if value not in (None, '') else None


def human_timeline_duration(seconds: float) -> str:
    remaining = max(0, int(round(seconds)))
    days, remaining = divmod(remaining, 86400)
    hours, remaining = divmod(remaining, 3600)
    minutes, seconds = divmod(remaining, 60)
    parts = []
    if days:
        parts.append(f'{days} day{"s" if days != 1 else ""}')
    if hours or parts:
        parts.append(f'{hours} hour{"s" if hours != 1 else ""}')
    if minutes or parts:
        parts.append(f'{minutes} minute{"s" if minutes != 1 else ""}')
    parts.append(f'{seconds} second{"s" if seconds != 1 else ""}')
    return ', '.join(parts)


def short_alert_id(alert_id: object) -> str:
    value = str(alert_id or '')
    if ':' in value:
        return value.rsplit(':', 1)[-1]
    return value[-16:] if len(value) > 16 else value


def alert_seen_timeline_html(row: sqlite3.Row | dict) -> str:
    """Render duplicate/repeat timing for a grouped alert detail panel."""
    events = row.get('member_timeline') if isinstance(row, dict) else None
    if not events:
        return ''
    normalized: list[dict[str, object]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        first_seen = str(event.get('first_seen') or '')
        last_seen = str(event.get('last_seen') or first_seen)
        fired_at = normalize_iso_display_text(event.get('timestamp') or event.get('fired_at') or last_seen or first_seen)
        point_ts = timeline_timestamp(fired_at) or timeline_timestamp(last_seen) or timeline_timestamp(first_seen)
        if point_ts is None:
            continue
        normalized.append({
            'alert_id': str(event.get('alert_id') or ''),
            'timestamp': fired_at or 'n/a',
            'first_seen': normalize_iso_display_text(first_seen or 'n/a'),
            'last_seen': normalize_iso_display_text(last_seen or first_seen or 'n/a'),
            'seen_count': max(1, safe_int(event.get('seen_count'))),
            'source_ip': str(event.get('source_ip') or 'n/a'),
            'destination_ip': str(event.get('destination_ip') or 'n/a'),
            'destination_port': str(event.get('destination_port') or 'n/a'),
            'point_ts': point_ts,
        })
    if len(normalized) <= 1:
        return ''
    normalized.sort(key=lambda event: (event['point_ts'], str(event['alert_id'])))
    first_ts = float(normalized[0]['point_ts'])
    last_ts = float(normalized[-1]['point_ts'])
    span = max(1.0, last_ts - first_ts)
    last_event_index = len(normalized)
    visual_bucket_width_pct = max(0.75, min(2.0, 100 / max(24, min(90, last_event_index))))
    visual_buckets: dict[int, dict[str, object]] = {}
    markers = []
    rows = []
    observation_index = 0
    for index, event in enumerate(normalized, start=1):
        point_ts = float(event['point_ts'])
        percent = 2 if span == 1.0 and last_ts == first_ts else max(2, min(98, round(((point_ts - first_ts) / span) * 100, 2)))
        # Dense repeat storms can produce many events within the same visual
        # time slice. Bucket nearby points for the rail, while the table below
        # retains every individual row for exact analyst review.
        bucket_key = int(round(percent / visual_bucket_width_pct))
        bucket = visual_buckets.setdefault(bucket_key, {
            'percent_sum': 0.0,
            'events': [],
            'observations': 0,
            'first_index': index,
            'last_index': index,
            'first_seen': event['first_seen'],
            'last_seen': event['last_seen'],
            'source_ip': event['source_ip'],
            'destination_ip': event['destination_ip'],
            'destination_port': event['destination_port'],
        })
        bucket['percent_sum'] = float(bucket['percent_sum']) + percent
        bucket['events'].append(event)
        bucket['observations'] = safe_int(bucket['observations']) + safe_int(event['seen_count'])
        bucket['first_index'] = min(safe_int(bucket['first_index']), index)
        bucket['last_index'] = max(safe_int(bucket['last_index']), index)
        bucket['first_seen'] = min(str(bucket['first_seen']), str(event['first_seen']))
        bucket['last_seen'] = max(str(bucket['last_seen']), str(event['last_seen']))
        repeat_count = max(1, safe_int(event['seen_count']))
        for repeat_index in range(1, repeat_count + 1):
            observation_index += 1
            title = (
                f"Stored alert row {index}, observation {repeat_index} of {repeat_count}"
                if repeat_count > 1 else f"Stored alert row {index}"
            )
            rows.append(
                f'<tr data-timeline-row data-timeline-index="{observation_index}" title="{html.escape(title, quote=True)}">'
                f'<td>{observation_index}</td>'
                f'<td>{html.escape(str(event["timestamp"]))}</td>'
                '<td>1</td>'
                f'<td><code>{html.escape(str(event["source_ip"]))}</code></td>'
                f'<td><code>{html.escape(str(event["destination_ip"]))}</code></td>'
                f'<td><code>{html.escape(str(event["destination_port"]))}</code></td>'
                f'<td><code>{html.escape(short_alert_id(event["alert_id"]))}</code></td>'
                '</tr>'
            )
    for bucket in sorted(visual_buckets.values(), key=lambda value: safe_int(value['first_index'])):
        bucket_events = bucket['events']
        event_count = len(bucket_events)
        observation_count = max(event_count, safe_int(bucket['observations']))
        percent = max(2, min(98, round(float(bucket['percent_sum']) / max(1, event_count), 2)))
        marker_size = max(8, min(28, round(7 + (math.log2(observation_count + 1) * 3.4))))
        contains_first = safe_int(bucket['first_index']) == 1
        contains_last = safe_int(bucket['last_index']) == last_event_index
        marker_classes = ['alert-timeline-marker']
        if contains_first:
            marker_classes.append('marker-first')
        if contains_last:
            marker_classes.append('marker-last')
        label = 'First' if contains_first else ('Last' if contains_last else (f'x{event_count}' if event_count > 1 else ''))
        title = (
            f"Events {bucket['first_index']}-{bucket['last_index']} | "
            f"observations {observation_count} | "
            f"{bucket['first_seen']} to {bucket['last_seen']} | "
            f"{bucket['source_ip']} -> {bucket['destination_ip']}:{bucket['destination_port']}"
        )
        markers.append(
            f'<span class="{" ".join(marker_classes)}" '
            f'style="left:{percent}%;--marker-size:{marker_size}px" title="{html.escape(title, quote=True)}">'
            f'{f"<span>{html.escape(label)}</span>" if label else ""}</span>'
        )
    seen_candidates = []
    for event in normalized:
        for key in ('first_seen', 'timestamp', 'last_seen'):
            display_value = str(event.get(key) or '')
            parsed_ts = timeline_timestamp(display_value)
            if parsed_ts is not None:
                seen_candidates.append((parsed_ts, display_value))
    first_seen_ts, first_seen_display = min(seen_candidates, default=(first_ts, str(normalized[0]['timestamp'])))
    last_seen_ts, last_seen_display = max(seen_candidates, default=(last_ts, str(normalized[-1]['timestamp'])))
    duration_text = human_timeline_duration(last_seen_ts - first_seen_ts)
    total_seen = sum(safe_int(event['seen_count']) for event in normalized)
    page_size = 25
    total_pages = max(1, math.ceil(total_seen / page_size))
    pagination_html = ''
    if total_seen > page_size:
        pagination_html = f'''
    <div class="alert-timeline-pagination" data-timeline-page-size="{page_size}" data-timeline-total="{total_seen}">
      <button class="timeline-page-button" type="button" data-timeline-prev disabled>Previous</button>
      <span data-timeline-page-label>Page 1 of {total_pages} · Showing 1-{min(page_size, total_seen)} of {total_seen}</span>
      <button class="timeline-page-button" type="button" data-timeline-next>Next</button>
    </div>'''
    return f'''
<details class="alert-timeline-section" aria-label="Duplicate alert timeline" data-timeline-page-size="{page_size}" open>
  <summary>Duplicate Alert Timeline <span>{len(normalized)} alert row(s), {total_seen} observation(s)</span></summary>
  <div class="alert-timeline-body">
    <dl class="alert-timeline-summary">
      <div><dt>First Seen:</dt><dd>{html.escape(first_seen_display)}</dd></div>
      <div><dt>Last Seen:</dt><dd>{html.escape(last_seen_display)}</dd></div>
      <div><dt>Duration:</dt><dd>{html.escape(duration_text)}</dd></div>
    </dl>
    <div class="alert-timeline-rail" aria-hidden="true">{''.join(markers)}</div>
    <div class="table-wrap alert-timeline-table"><table><thead><tr><th>#</th><th>Timestamp</th><th>Seen</th><th>Source IP</th><th>Destination IP</th><th>Destination Port</th><th>Alert</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
    {pagination_html}
  </div>
</details>
'''


def passthrough_markdown_report_text(text: str) -> str:
    # Kept for compatibility with the existing render path. Full-fidelity mode
    # intentionally renders report text without redacting alert fields.
    return text


def alert_detail_markdown(raw: dict) -> str:
    event = raw_event_for_details(raw)
    sections: list[str] = []
    sections.extend(detail_table('Security Onion Detail Fields', [
        ('Message', raw.get('message') or event.get('message')),
        ('Tags', raw.get('tags') or event.get('tags')),
        ('Event action', nested_object(event, 'event', 'action')),
        ('Event kind', nested_object(event, 'event', 'kind')),
        ('Event type', nested_object(event, 'event', 'type')),
        ('Event outcome', nested_object(event, 'event', 'outcome')),
        ('Module', raw.get('event_module') or nested_object(event, 'event', 'module')),
        ('Dataset', raw.get('event_dataset') or nested_object(event, 'event', 'dataset')),
        ('Rule category', raw.get('rule_category') or nested_object(event, 'rule', 'category')),
        ('Rule action', raw.get('rule_action') or nested_object(event, 'rule', 'action')),
        ('Rule ruleset', raw.get('rule_ruleset') or nested_object(event, 'rule', 'ruleset')),
        ('Rule reference', raw.get('rule_reference') or nested_object(event, 'rule', 'reference')),
        ('Rule metadata', raw.get('rule_metadata') or nested_object(event, 'rule', 'metadata')),
    ]))
    sections.extend(detail_table('Network And Flow Details', [
        ('Transport', nested_object(raw, 'network', 'transport') or nested_object(event, 'network', 'transport')),
        ('Community ID', nested_object(raw, 'network', 'community_id') or nested_object(event, 'network', 'community_id')),
        ('VLAN', nested_object(raw, 'network', 'vlan') or nested_object(event, 'network', 'vlan')),
        ('Direction', nested_object(event, 'network', 'direction')),
        ('Protocol', nested_object(event, 'network', 'protocol') or nested_object(event, 'suricata', 'eve', 'proto')),
        ('Application protocol', nested_object(event, 'suricata', 'eve', 'app_proto')),
        ('Source ASN/org', [nested_object(raw, 'source', 'asn'), nested_object(raw, 'source', 'org')]),
        ('Source geo', nested_object(event, 'source', 'geo')),
        ('Destination ASN/org', [nested_object(raw, 'destination', 'asn'), nested_object(raw, 'destination', 'org')]),
        ('Destination geo', nested_object(event, 'destination', 'geo')),
        ('Flow', nested_object(event, 'suricata', 'eve', 'flow')),
        ('Flow ID', nested_object(event, 'suricata', 'eve', 'flow_id')),
        ('Related IPs', nested_object(event, 'related', 'ip') or nested_object(raw, 'related', 'ip')),
    ]))
    sections.extend(detail_table('Protocol Details', [
        ('DNS', raw.get('dns') or event.get('dns') or nested_object(event, 'suricata', 'eve', 'dns')),
        ('HTTP', raw.get('http') or event.get('http') or nested_object(event, 'suricata', 'eve', 'http')),
        ('URL', raw.get('url') or event.get('url')),
        ('TLS', raw.get('tls') or event.get('tls') or nested_object(event, 'suricata', 'eve', 'tls')),
    ], max_len=700))
    sections.extend(detail_table('Host And Sensor Details', [
        ('Host', raw.get('host') or event.get('host')),
        ('Observer', raw.get('observer') or event.get('observer')),
        ('Agent', raw.get('agent') or event.get('agent')),
        ('Log', raw.get('log') or event.get('log')),
        ('User', raw.get('user') or event.get('user')),
        ('Process', raw.get('process') or event.get('process')),
        ('File', raw.get('file') or event.get('file')),
    ], max_len=700))
    sections.extend(detail_table('Threat Context', [
        ('Threat', raw.get('threat') or event.get('threat')),
        ('Related hosts', nested_object(event, 'related', 'hosts') or nested_object(raw, 'related', 'hosts')),
        ('Related hashes', nested_object(event, 'related', 'hash') or nested_object(raw, 'related', 'hash')),
        ('Suricata alert', nested_object(event, 'suricata', 'eve', 'alert')),
        ('Security Onion enrichment note', nested_value(raw, 'security_onion', 'enrichment_note')),
    ], max_len=700))
    if not sections:
        return ''
    return '\n'.join(['## Enriched Alert Details', '', *sections]).strip()


def public_enrichment_markdown(raw: dict, enrichment_json: object = None) -> str:
    external_intel = nested_object(raw, 'enrichment', 'external_intel')
    if not isinstance(external_intel, dict) or (
        not external_intel.get('records')
        and not external_intel.get('skipped')
        and not external_intel.get('errors')
    ):
        enrichment_record = json_object(enrichment_json)
        stored_external_intel = enrichment_record.get('external_intel')
        if isinstance(stored_external_intel, dict):
            external_intel = stored_external_intel
    if not isinstance(external_intel, dict):
        return ''
    records = external_intel.get('records') if isinstance(external_intel.get('records'), list) else []
    skipped = external_intel.get('skipped') if isinstance(external_intel.get('skipped'), list) else []
    errors = external_intel.get('errors') if isinstance(external_intel.get('errors'), list) else []
    if not records and not skipped and not errors:
        return '\n'.join([
            '## Public Enrichment',
            '',
            'No public enrichment lookups were applicable for this alert.',
        ])
    lines = ['## Public Enrichment', '']
    if records:
        lines.extend([
            '| Source | Indicator | Type | Verdict | Confidence | Tags | Cached |',
            '| --- | --- | --- | --- | --- | --- | --- |',
        ])
        for record in records[:24]:
            if not isinstance(record, dict):
                continue
            tags = record.get('tags') if isinstance(record.get('tags'), list) else []
            lines.append(
                f'| {markdown_cell(record.get("source"))} | '
                f'{markdown_cell(record.get("indicator"), 120)} | '
                f'{markdown_cell(record.get("indicator_type"))} | '
                f'{markdown_cell(record.get("verdict"))} | '
                f'{markdown_cell(record.get("confidence"))} | '
                f'{markdown_cell(", ".join(str(tag) for tag in tags if str(tag).strip()), 180)} | '
                f'{markdown_cell(normalize_iso_display_text(record.get("cached_at") or ""))} |'
            )
        lines.append('')
    skipped_rows = []
    for item in [*skipped, *errors]:
        if isinstance(item, dict):
            skipped_rows.append(item)
    if skipped_rows:
        lines.extend([
            '### Skipped / Limits',
            '',
            '| Source | Indicator | Reason | Limit note |',
            '| --- | --- | --- | --- |',
        ])
        for item in skipped_rows[:32]:
            lines.append(
                f'| {markdown_cell(item.get("source"))} | '
                f'{markdown_cell(item.get("indicator"), 120)} | '
                f'{markdown_cell(item.get("reason"), 220)} | '
                f'{markdown_cell(item.get("limit_note"), 260)} |'
            )
        lines.append('')
    return '\n'.join(lines).strip()


def public_enrichment_has_content(enrichment_json: object) -> bool:
    enrichment_record = json_object(enrichment_json)
    external_intel = enrichment_record.get('external_intel')
    if not isinstance(external_intel, dict):
        return False
    return any(
        isinstance(external_intel.get(key), list) and len(external_intel.get(key)) > 0
        for key in ('records', 'skipped', 'errors')
    )


def public_enrichment_status(enrichment_json: object) -> tuple[str, str, str, int, int, int]:
    enrichment_record = json_object(enrichment_json)
    external_intel = enrichment_record.get('external_intel')
    if not isinstance(external_intel, dict):
        return ('none', 'None', 'No public enrichment data recorded for this alert group', 0, 0, 0)

    records = external_intel.get('records') if isinstance(external_intel.get('records'), list) else []
    skipped = external_intel.get('skipped') if isinstance(external_intel.get('skipped'), list) else []
    errors = external_intel.get('errors') if isinstance(external_intel.get('errors'), list) else []
    indicators = external_intel.get('indicators') if isinstance(external_intel.get('indicators'), dict) else {}
    indicator_count = sum(
        len(indicators.get(key) or [])
        for key in ('public_ips', 'domains', 'urls', 'hashes', 'cves')
        if isinstance(indicators.get(key), list)
    )

    if records:
        detail = f'{len(records)} enrichment record(s), {len(skipped)} skipped source(s), {len(errors)} error(s)'
        return ('enriched', 'Enriched', detail, len(records), len(skipped), len(errors))
    if errors:
        detail = f'{len(errors)} enrichment error(s), {len(skipped)} skipped source(s)'
        return ('error', 'Error', detail, 0, len(skipped), len(errors))
    if skipped:
        detail = f'Indicators found, but {len(skipped)} source(s) skipped or unavailable'
        return ('checked', 'Checked', detail, 0, len(skipped), 0)
    if indicator_count:
        return ('pending', 'Pending', f'{indicator_count} public indicator(s) found with no completed enrichment records yet', 0, 0, 0)
    return ('none', 'None', 'No public indicators were recorded for enrichment', 0, 0, 0)


def directory_size_bytes(path: Path) -> int:
    """Return total bytes for a runtime evidence directory without following symlinks."""
    if not path.exists():
        return 0
    total = 0
    for item in path.rglob('*'):
        try:
            if item.is_file() and not item.is_symlink():
                total += item.stat().st_size
        except OSError:
            continue
    return total


def pcap_analysis_index() -> dict[str, set[str]]:
    """Index parsed PCAP evidence once per dashboard build for fast row lookups."""
    index = {'request_ids': set(), 'alert_ids': set(), 'group_ids': set()}
    if not PCAP_ANALYSIS_DIR.exists():
        return index
    for path in PCAP_ANALYSIS_DIR.glob('*-pcap-analysis.json'):
        try:
            record = json.loads(path.read_text(encoding='utf-8'))
        except Exception:
            continue
        if not isinstance(record, dict):
            continue
        request = record.get('request') if isinstance(record.get('request'), dict) else {}
        for key, bucket in (('request_id', 'request_ids'), ('alert_id', 'alert_ids'), ('group_id', 'group_ids')):
            value = str(request.get(key) or '').strip()
            if value:
                index[bucket].add(value)
    return index


def pcap_request_status_for_row(row: sqlite3.Row | dict) -> str:
    """Return the newest broker status for the row's group or representative alert."""
    if not DB_PATH.exists():
        return ''
    group_id = hashlib.sha1((row['alert_group_key'] or alert_group_key(row)).encode('utf-8')).hexdigest()[:12]
    alert_id = str(row['alert_id'] or '').strip()
    try:
        with sqlite3.connect(f'file:{DB_PATH}?mode=ro', uri=True, timeout=2) as conn:
            conn.row_factory = sqlite3.Row
            exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pcap_requests'").fetchone()
            if not exists:
                return ''
            found = conn.execute(
                """
                SELECT status
                FROM pcap_requests
                WHERE group_id = ? OR alert_id = ?
                ORDER BY COALESCE(completed_at, updated_at, created_at) DESC
                LIMIT 1
                """,
                (group_id, alert_id),
            ).fetchone()
    except sqlite3.Error:
        return ''
    return str(found['status'] or '').strip().lower() if found else ''


def pcap_status_for_row(row: sqlite3.Row | dict, index: dict[str, set[str]] | None = None) -> tuple[str, str, str]:
    """Return a compact PCAP analysis status for the alert table."""
    pcap_index = index or pcap_analysis_index()
    group_id = hashlib.sha1((row['alert_group_key'] or alert_group_key(row)).encode('utf-8')).hexdigest()[:12]
    alert_id = str(row['alert_id'] or '').strip()
    if group_id in pcap_index.get('group_ids', set()) or alert_id in pcap_index.get('alert_ids', set()):
        return ('analyzed', 'Analyzed', 'Parsed Zeek/TShark PCAP analysis is available for this detection group')
    request_status = pcap_request_status_for_row(row)
    if request_status in {'pending', 'claimed', 'fulfilled'}:
        label = 'Queued' if request_status in {'pending', 'claimed'} else 'Parsing'
        return ('queued', label, f'PCAP request is {request_status}; parsed analysis is not available yet')
    if request_status == 'failed':
        return ('error', 'Failed', 'PCAP request failed before parsed analysis was produced')
    return ('none', 'None', 'No parsed PCAP analysis is available for this detection group')


def sqlite_report_markdown(row: sqlite3.Row | dict, raw: dict, ai_analysis: dict | None) -> str:
    # Render a DB-only alert detail for suppressed/dropped/duplicate rows.
    alert_json = json.dumps(raw or {'alert_json': row['alert_json']}, indent=2, sort_keys=True)
    status = row['filter_status'] or 'stored'
    enriched_details = alert_detail_markdown(raw)
    public_enrichment = public_enrichment_markdown(raw, row_value(row, 'enrichment_json'))
    ai_details = ai_analysis_report_markdown(ai_analysis)
    bottom_evidence = bottom_evidence_markdown(raw, alert_json)
    ai_response_json = complete_ai_response_json_markdown(ai_analysis)
    lines = [
        '---',
        'type: soc-alert-db-record',
        f'alert_id: {json.dumps(row["alert_id"])}',
        f'triage_level: {json.dumps((row["triage_level"] or row["severity_label"] or "informational").lower())}',
        f'status: {json.dumps(status)}',
        f'source_ip: {json.dumps(row["source_ip"] or "")}',
        f'destination_ip: {json.dumps(row["destination_ip"] or "")}',
        'tags:',
        '  - security-onion',
        '  - soc-alert',
        '  - sqlite-generated',
        '---',
        '',
        f'# [{severity_label_from_row(row).upper()}] {row["rule_name"] or "Security Onion Alert"}',
        '',
        '- **Dashboard source:** SQLite alert-store',
        f'- **Alert ID:** {row["alert_id"]}',
        f'- **Workflow status:** {status}',
        f'- **Filter reason:** {row["filter_reason"] or "n/a"}',
        f'- **Suppression key:** {row["suppression_key"] or "n/a"}',
        f'- **Route:** {row["routing"] or "n/a"}',
        f'- **Score:** {row["triage_score"] if row["triage_score"] is not None else "n/a"}',
        f'- **Traffic:** {row["source_ip"] or "n/a"} -> {row["destination_ip"] or "n/a"}',
        '',
        '## Alert Summary',
        '',
        '| Field | Value |',
        '| --- | --- |',
        f'| Rule name | {row["rule_name"] or "n/a"} |',
        f'| Event dataset | {row["event_dataset"] or "n/a"} |',
        f'| Severity | {row["severity"] if row["severity"] is not None else "n/a"} |',
        f'| Severity label | {row["severity_label"] or "n/a"} |',
        f'| Triage level | {row["triage_level"] or "n/a"} |',
        f'| First seen | {row["first_seen"] or "n/a"} |',
        f'| Last seen | {row["last_seen"] or "n/a"} |',
        f'| Seen count | {row["seen_count"] if row["seen_count"] is not None else "n/a"} |',
        f'| Grouped alert rows | {row.get("raw_alert_count", "n/a") if isinstance(row, dict) else "n/a"} |',
        '',
        ai_details,
        '',
        public_enrichment,
        '',
        enriched_details,
        '',
        '## Analyst Notes',
        '',
        '- [ ] Review whether this DB-only record needs a Markdown investigation note.',
        '- [ ] If this is recurring benign noise, tune `scoring_rules.json` rather than hiding evidence.',
        '',
        bottom_evidence,
        '',
        ai_response_json,
        '',
    ]
    return '\n'.join(lines)


def report_from_sqlite_row(
    row: sqlite3.Row | dict,
    markdown_by_alert_id: dict[str, tuple[Path, str, os.stat_result]],
    ai_analysis_by_alert_id: dict[str, dict],
    ai_prompts_by_alert_id: dict[str, dict],
    running_ai_alert_ids: set[str],
    pcap_index: dict[str, set[str]] | None = None,
) -> AlertReport:
    # One SQLite row becomes one UI row. Matching Markdown is optional; suppressed
    # and dropped records often have no Markdown by design.
    raw = raw_alert_object(row)
    raw_alert_count = safe_int(row['raw_alert_count'])
    total_seen_count = safe_int(row['total_seen_count'])
    repeat_count = max(raw_alert_count, total_seen_count, safe_int(row['seen_count']))
    row_first_seen = row['first_seen'] or 'n/a'
    row_last_seen = row['last_seen'] or 'n/a'
    alert_group = row['alert_group_key'] or alert_group_key(row)
    markdown = markdown_by_alert_id.get(row['alert_id'])
    ai_analysis = ai_analysis_for_row(row, ai_analysis_by_alert_id)
    ai_response = ai_analysis.get('response') if isinstance(ai_analysis, dict) and isinstance(ai_analysis.get('response'), dict) else {}
    recommended_tuning_actions = [
        str(action).strip()
        for action in (ai_response.get('recommended_tuning_actions') if isinstance(ai_response.get('recommended_tuning_actions'), list) else [])
        if str(action).strip()
    ]
    ai_status_key, ai_status_label, ai_status_detail = ai_workflow_status_for_row(row, ai_analysis_by_alert_id, ai_prompts_by_alert_id, running_ai_alert_ids)
    enrichment_status_key, enrichment_status_label, enrichment_status_detail, enrichment_record_count, enrichment_skip_count, enrichment_error_count = public_enrichment_status(row['enrichment_json'])
    pcap_status_key, pcap_status_label, pcap_status_detail = pcap_status_for_row(row, pcap_index)
    ai_details = ai_analysis_report_markdown(ai_analysis)
    ai_response_json = complete_ai_response_json_markdown(ai_analysis)
    timeline_html = alert_seen_timeline_html(row)
    if markdown:
        source, text, stat = markdown
        text = passthrough_markdown_report_text(text)
        text = remove_markdown_sections(text, {'raw alert', 'complete alert json', 'complete ai response json'}).rstrip()
        rel_source = source.name
        for source_dir in MARKDOWN_SOURCES:
            if source_dir in source.parents or source == source_dir:
                rel_source = str(source.relative_to(source_dir))
                break
        if '## AI Model Used' not in text:
            text = f'{text.rstrip()}\n\n{ai_details}\n'
        enriched_details = alert_detail_markdown(raw)
        public_enrichment = public_enrichment_markdown(raw, row['enrichment_json'])
        if public_enrichment and '## Public Enrichment' not in text:
            text = f'{text.rstrip()}\n\n{public_enrichment}\n'
        if enriched_details and '## Enriched Alert Details' not in text:
            text = f'{text.rstrip()}\n\n{enriched_details}\n'
        text = f'{text.rstrip()}\n\n{bottom_evidence_markdown(raw, row["alert_json"])}'
        if ai_response_json:
            text = f'{text.rstrip()}\n\n{ai_response_json}'
        text = f'{text.rstrip()}\n'
        text = normalize_iso_display_text(text)
        rendered_html = markdown_to_html(text)
        if timeline_html:
            rendered_html = rendered_html.replace('<h2>AI Model Used</h2>', timeline_html + '<h2>AI Model Used</h2>', 1)
            if timeline_html not in rendered_html:
                rendered_html = timeline_html + rendered_html
        size = stat.st_size
    else:
        source = DB_PATH
        rel_source = 'SQLite alert-store'
        row_for_markdown = dict(row)
        row_for_markdown['first_seen'] = row_first_seen
        row_for_markdown['last_seen'] = row_last_seen
        row_for_markdown['seen_count'] = repeat_count
        row_for_markdown['raw_alert_count'] = raw_alert_count
        row_for_markdown['member_timeline'] = row.get('member_timeline') if isinstance(row, dict) else []
        text = sqlite_report_markdown(row_for_markdown, raw, ai_analysis)
        text = normalize_iso_display_text(text)
        rendered_html = markdown_to_html(text)
        if timeline_html:
            rendered_html = rendered_html.replace('<h2>AI Model Used</h2>', timeline_html + '<h2>AI Model Used</h2>', 1)
            if timeline_html not in rendered_html:
                rendered_html = timeline_html + rendered_html
        size = len(row['alert_json'] or '')

    criticality = severity_label_from_row(row)
    criticality_rank = CRITICALITY_ORDER.get(criticality.lower(), CRITICALITY_ORDER['informational'])
    title = f'[{criticality.upper()}] {row["rule_name"] or "Security Onion Alert"}'
    status = row['filter_status'] or 'stored'
    filter_reason = row['filter_reason'] or 'no filter reason recorded'
    summary = f'{status}: {filter_reason}. Seen {repeat_count} time(s). {summarize_markdown(text, 160)}'
    source_port = clean_endpoint_part(row['source_port'] or nested_value(raw, 'source', 'port'))
    destination_port = clean_endpoint_part(row['destination_port'] or nested_value(raw, 'destination', 'port'))
    source_ip = clean_endpoint_part(row['source_ip'] or nested_value(raw, 'source', 'ip'))
    destination_ip = clean_endpoint_part(row['destination_ip'] or nested_value(raw, 'destination', 'ip'))
    alert_source = clean_endpoint_part(row['event_dataset'] or nested_value(raw, 'event', 'dataset') or nested_value(raw, 'security_onion', 'event_dataset'))
    rule_id = clean_endpoint_part(nested_value(raw, 'rule_id'))
    alert_ts = parse_iso_timestamp(row['last_seen']) or parse_iso_timestamp(row['timestamp']) or dt.datetime.now(dt.timezone.utc).timestamp()
    # Analyst state is tracked at the grouped-detection level so acknowledge
    # and suppression state survives when a newer matching alert becomes the
    # representative row.
    digest = hashlib.sha1(alert_group.encode('utf-8')).hexdigest()[:12]

    return AlertReport(
        title=title,
        source=source,
        rel_source=rel_source,
        mtime=alert_ts,
        size=size,
        digest=digest,
        rendered_html=rendered_html,
        summary=summary,
        criticality=criticality,
        criticality_rank=criticality_rank,
        alert_source=alert_source or 'n/a',
        filter_status=(row['filter_status'] or 'accepted'),
        source_ip=source_ip,
        source_port=source_port,
        destination_ip=destination_ip,
        destination_port=destination_port,
        source_endpoint=endpoint_label(source_ip, source_port),
        destination_endpoint=endpoint_label(destination_ip, destination_port),
        rule_id=rule_id,
        rule_name=row['rule_name'] or title,
        raw_alert_count=raw_alert_count,
        total_seen_count=total_seen_count,
        repeat_count=repeat_count,
        first_seen=row_first_seen,
        last_seen=row_last_seen,
        alert_group_key=alert_group,
        alert_ts=alert_ts,
        ai_status_key=ai_status_key,
        ai_status_label=ai_status_label,
        ai_status_detail=ai_status_detail,
        enrichment_status_key=enrichment_status_key,
        enrichment_status_label=enrichment_status_label,
        enrichment_status_detail=enrichment_status_detail,
        enrichment_record_count=enrichment_record_count,
        enrichment_skip_count=enrichment_skip_count,
        enrichment_error_count=enrichment_error_count,
        pcap_status_key=pcap_status_key,
        pcap_status_label=pcap_status_label,
        pcap_status_detail=pcap_status_detail,
        tuning_recommendation=str(ai_response.get('tuning_recommendation') or 'none').strip().lower(),
        tuning_reason=str(ai_response.get('tuning_reason') or '').strip(),
        recommended_tuning_actions=recommended_tuning_actions,
    )


def load_markdown_only_reports() -> list[AlertReport]:
    # Backward-compatible fallback for disaster recovery if the SQLite DB has
    # not been restored yet but Markdown reports are present.
    reports: list[AlertReport] = []
    for source_dir in MARKDOWN_SOURCES:
        for path in sorted(source_dir.rglob('*'), key=lambda p: str(p).lower()):
            if not path.is_file() or path.suffix.lower() not in SUPPORTED_SUFFIXES or path.name.startswith('.'):
                continue
            try:
                text = path.read_text(encoding='utf-8')
            except UnicodeDecodeError:
                text = path.read_text(encoding='utf-8', errors='replace')
            stat = path.stat()
            digest = hashlib.sha1(str(path).encode('utf-8')).hexdigest()[:12]
            try:
                rel_source = str(path.relative_to(source_dir))
            except ValueError:
                rel_source = path.name
            title = clean_title_from_markdown(text, path)
            criticality, criticality_rank = detect_criticality(text, title, path)
            source_ip, source_port, destination_ip, destination_port = extract_network_endpoints(text)
            source_endpoint = endpoint_label(source_ip, source_port)
            destination_endpoint = endpoint_label(destination_ip, destination_port)
            rule_id, rule_name = extract_rule_identity(text, title)
            alert_ts = extract_alert_timestamp(text, stat.st_mtime)
            reports.append(AlertReport(
                title=title,
                source=path,
                rel_source=rel_source,
                mtime=stat.st_mtime,
                size=stat.st_size,
                digest=digest,
                rendered_html=markdown_to_html(text),
                summary=summarize_markdown(text),
                criticality=criticality,
                criticality_rank=criticality_rank,
                alert_source='markdown',
                filter_status='markdown',
                source_ip=source_ip,
                source_port=source_port,
                destination_ip=destination_ip,
                destination_port=destination_port,
                source_endpoint=source_endpoint,
                destination_endpoint=destination_endpoint,
                rule_id=rule_id,
                rule_name=rule_name,
                raw_alert_count=1,
                total_seen_count=1,
                repeat_count=1,
                first_seen='n/a',
                last_seen='n/a',
                alert_group_key=rule_name,
                alert_ts=alert_ts,
                ai_status_key='not-queued',
                ai_status_label='Not queued',
                ai_status_detail='SQLite alert-store is unavailable; AI status cannot be resolved',
                enrichment_status_key='none',
                enrichment_status_label='None',
                enrichment_status_detail='SQLite alert-store is unavailable; enrichment status cannot be resolved',
                enrichment_record_count=0,
                enrichment_skip_count=0,
                enrichment_error_count=0,
                pcap_status_key='none',
                pcap_status_label='None',
                pcap_status_detail='SQLite alert-store is unavailable; PCAP analysis status cannot be resolved',
                tuning_recommendation='none',
                tuning_reason='',
                recommended_tuning_actions=[],
            ))
    return sorted(reports, key=lambda r: (r.criticality_rank, r.mtime, r.title.lower()), reverse=True)


def load_reports() -> list[AlertReport]:
    # SQLite is the normal source of truth for dashboard rows. Markdown is
    # supplementary detail/corpus content, not the table database.
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if not DB_PATH.exists():
        return load_markdown_only_reports()

    markdown_by_alert_id = load_markdown_reports_by_alert_id()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        columns = {row[1] for row in conn.execute('PRAGMA table_info(alerts)').fetchall()}
        total_seen_expr = 'total_seen_count' if 'total_seen_count' in columns else '0'
        source_port_expr = 'source_port' if 'source_port' in columns else 'NULL'
        destination_port_expr = 'destination_port' if 'destination_port' in columns else 'NULL'
        network_protocol_expr = 'network_protocol' if 'network_protocol' in columns else 'NULL'
        transport_protocol_expr = 'transport_protocol' if 'transport_protocol' in columns else 'NULL'
        rows = conn.execute(
            f'''
            SELECT alert_id, first_seen, last_seen, seen_count, {total_seen_expr} AS total_seen_count,
                   timestamp, rule_name, event_dataset, severity, severity_label, source_ip, destination_ip,
                   {source_port_expr} AS source_port, {destination_port_expr} AS destination_port,
                   {network_protocol_expr} AS network_protocol, {transport_protocol_expr} AS transport_protocol,
                   alert_json, traffic_direction, triage_score, triage_level, routing,
                   filter_status, filter_reason, suppression_key, enrichment_json
            FROM alerts
            ORDER BY replace(replace(COALESCE(last_seen, timestamp, first_seen), 'T', ' '), 'Z', '') DESC, alert_id DESC
            '''
        ).fetchall()
    finally:
        conn.close()
    grouped_by_key: dict[str, list[sqlite3.Row]] = {}
    for row in rows:
        grouped_by_key.setdefault(alert_group_key(row), []).append(row)
    aggregated_rows: list[dict[str, object]] = []
    for key, members in grouped_by_key.items():
        # `members[0]` is the newest alert in this group because the source
        # query is ordered by last_seen descending. Keep it as the representative
        # so the table row reflects the newest event while Count covers the
        # whole grouped detection.
        representative = members[0]
        raw_alert_count = len(members)
        total_seen = 0
        member_timeline: list[dict[str, object]] = []
        earliest_first_seen = representative['first_seen']
        latest_last_seen = representative['last_seen']
        earliest_first_ts = parse_iso_timestamp(earliest_first_seen)
        latest_last_ts = parse_iso_timestamp(latest_last_seen)
        for member in members:
            member_seen_count = max(1, safe_int(member['seen_count']), safe_int(member['total_seen_count']))
            total_seen += member_seen_count
            member_first_seen = member['first_seen']
            member_last_seen = member['last_seen']
            member_raw = raw_alert_object(member)
            member_timeline.append({
                'alert_id': member['alert_id'],
                'timestamp': member['timestamp'] or member_last_seen or member_first_seen,
                'first_seen': member_first_seen,
                'last_seen': member_last_seen,
                'seen_count': member_seen_count,
                'source_ip': member['source_ip'] or nested_value(member_raw, 'source', 'ip') or 'n/a',
                'destination_ip': member['destination_ip'] or nested_value(member_raw, 'destination', 'ip') or 'n/a',
                'destination_port': clean_endpoint_part(member['destination_port'] or nested_value(member_raw, 'destination', 'port')),
            })
            member_first_ts = parse_iso_timestamp(member_first_seen)
            member_last_ts = parse_iso_timestamp(member_last_seen)
            if earliest_first_ts is None or (member_first_ts is not None and member_first_ts < earliest_first_ts):
                earliest_first_seen = member_first_seen
                earliest_first_ts = member_first_ts
            if latest_last_ts is None or (member_last_ts is not None and member_last_ts > latest_last_ts):
                latest_last_seen = member_last_seen
                latest_last_ts = member_last_ts
        row_dict = dict(representative)
        enriched_member = next((member for member in members if public_enrichment_has_content(member['enrichment_json'])), None)
        if enriched_member is not None and not public_enrichment_has_content(row_dict.get('enrichment_json')):
            row_dict['enrichment_json'] = enriched_member['enrichment_json']
        row_dict['raw_alert_count'] = raw_alert_count
        row_dict['total_seen_count'] = total_seen
        row_dict['repeat_count'] = max(raw_alert_count, total_seen)
        row_dict['member_alert_ids'] = [member['alert_id'] for member in members]
        row_dict['member_timeline'] = member_timeline
        row_dict['first_seen'] = earliest_first_seen or representative['first_seen'] or 'n/a'
        row_dict['last_seen'] = latest_last_seen or representative['last_seen'] or 'n/a'
        row_dict['alert_group_key'] = key
        aggregated_rows.append(row_dict)
    ai_analysis_by_alert_id = load_ai_analysis_by_alert_id()
    ai_prompts_by_alert_id = load_ai_prompts_by_alert_id()
    running_ai_alert_ids = running_ai_prompt_alert_ids(ai_prompts_by_alert_id)
    pcap_index = pcap_analysis_index()
    reports = [report_from_sqlite_row(row, markdown_by_alert_id, ai_analysis_by_alert_id, ai_prompts_by_alert_id, running_ai_alert_ids, pcap_index) for row in aggregated_rows]
    return sorted(reports, key=lambda r: (r.criticality_rank, r.mtime, r.title.lower()), reverse=True)

def human_size(num: int) -> str:
    n = float(num)
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB':
            return f'{n:.1f} {unit}' if unit != 'B' else f'{int(n)} B'
        n /= 1024
    return f'{n:.1f} GB'


def human_time(ts: float) -> str:
    return format_project_timestamp(dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).replace(microsecond=0))


def iso_local_time(ts: float) -> str:
    """Render alert timestamps in local ISO 8601 with the project separator."""
    value = dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc)
    return format_project_timestamp(value)


def last_seen_ts_for(report: AlertReport) -> float:
    # `last_seen` is the grouped newest alert timestamp. `alert_ts` is the
    # representative-row fallback if older SQLite rows have sparse timestamps.
    return parse_iso_timestamp(report.last_seen) or report.alert_ts or report.mtime


def last_seen_iso_for(report: AlertReport) -> str:
    return iso_local_time(last_seen_ts_for(report))


def compact_minute_timestamp(value: str) -> str:
    """Render a timestamp as `YYYY-MM-DD  HH:MM-06:00` for compact metric cards."""
    parsed = parse_iso_datetime(value)
    text = format_project_timestamp(parsed) if parsed else str(value or '')
    match = re.search(r'(\d{4}-\d{2}-\d{2})(?:T|\s+)(\d{2}:\d{2})(?::\d{2}(?:\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?', text)
    if not match:
        return text
    date, minute, offset = match.groups()
    return f'{date}  {minute}{offset or ""}'



def ai_summary_for(report: AlertReport) -> str:
    title = report.title.lower()
    if 'cins active threat' in title or 'poor reputation' in title:
        return 'IP reputation hit observed in threat intelligence feeds. Review related SSH or external connection activity.'
    if 'ssh scan outbound' in title:
        return 'Outbound SSH scanning activity detected. Multiple destination attempts may indicate reconnaissance or misconfiguration.'
    if 'potential ssh scan' in title:
        return 'SSH scanning behavior identified. Review source host, destination spread, and authentication telemetry.'
    if 'telegram api certificate' in title:
        return 'Telegram API certificate observed in traffic. Validate expected application use and possible exfiltration channel.'
    if 'curl user-agent' in title or 'dotted quad' in title:
        return 'Direct-IP curl-style traffic observed. Review process context and destination reputation.'
    if 'abused hosting domain' in title or 'azurewebsites' in title:
        return 'Potential abused hosting infrastructure observed. Review DNS/TLS context and related endpoint activity.'
    return report.summary[:170] + ('…' if len(report.summary) > 170 else '')


def risk_score_for(report: AlertReport) -> int:
    haystack = f'{report.title}\n{report.summary}'
    score_match = re.search(r'triage\s+score\s*[:=]\s*["\']?(\d{1,3})\b', haystack, flags=re.IGNORECASE)
    if score_match:
        return max(0, min(100, int(score_match.group(1))))
    return {5: 92, 4: 78, 3: 58, 2: 32, 1: 12}.get(report.criticality_rank, 12)


def ai_status_pill(report: AlertReport) -> str:
    return (
        f'<span class="ai-status-pill ai-status-{html.escape(report.ai_status_key)}" '
        f'title="{html.escape(report.ai_status_detail, quote=True)}">'
        f'{html.escape(report.ai_status_label)}</span>'
    )


def enrichment_status_pill(report: AlertReport) -> str:
    return (
        f'<span class="enrichment-status-pill enrichment-status-{html.escape(report.enrichment_status_key)}" '
        f'title="{html.escape(report.enrichment_status_detail, quote=True)}">'
        f'{html.escape(report.enrichment_status_label)}</span>'
    )


def pcap_status_pill(report: AlertReport) -> str:
    return (
        f'<span class="pcap-status-pill pcap-status-{html.escape(report.pcap_status_key)}" '
        f'title="{html.escape(report.pcap_status_detail, quote=True)}">'
        f'{html.escape(report.pcap_status_label)}</span>'
    )


def ai_activity_state(reports: list[AlertReport]) -> dict[str, object]:
    """Summarize AI queue state for both static rendering and live polling."""
    counts = {
        'analyzing': sum(1 for report in reports if report.ai_status_key == 'analyzing'),
        'queued': sum(1 for report in reports if report.ai_status_key == 'queued'),
        'analyzed': sum(1 for report in reports if report.ai_status_key == 'analyzed'),
        'not_queued': sum(1 for report in reports if report.ai_status_key == 'not-queued'),
        'total': len(reports),
    }
    active = counts['analyzing'] > 0
    model = current_local_ai_model()
    status_label = 'Analyzing' if active else 'Idle'
    return {
        'active': active,
        'label': 'AI Alert Triage',
        'detail': f'{status_label} · Model: {model}',
        'model': model,
        'counts': counts,
    }


def render_ai_activity_metric(state: dict[str, object]) -> str:
    return render_ai_activity_metric_card(state, current_local_ai_model())


def pct(part: int | float, total: int | float) -> int:
    """Return a rounded percent while avoiding divide-by-zero noise."""
    if not total:
        return 0
    return round((part / total) * 100)


def counter_top(items: list[tuple[str, int]], limit: int = 6) -> list[tuple[str, int]]:
    """Aggregate label/value pairs and return the largest entries."""
    totals: dict[str, int] = {}
    for label, value in items:
        cleaned = str(label or 'n/a').strip() or 'n/a'
        totals[cleaned] = totals.get(cleaned, 0) + int(value or 0)
    return sorted(totals.items(), key=lambda item: (item[1], item[0].lower()), reverse=True)[:limit]


def executive_donut(title: str, center: str, subtitle: str, rows: list[tuple[str, int, str]]) -> str:
    total = sum(value for _label, value, _class_name in rows)
    if total <= 0:
        rows = [('No data', 1, 'info')]
        total = 1
    offset = 25
    segments = []
    legend = []
    circumference = 100
    for label, value, class_name in rows:
        if value <= 0:
            continue
        dash = max(0.5, (value / total) * circumference)
        segments.append(
            f'<circle class="donut-segment donut-{html.escape(class_name)}" cx="18" cy="18" r="15.915" '
            f'stroke-dasharray="{dash:.3f} {circumference - dash:.3f}" stroke-dashoffset="{offset:.3f}"></circle>'
        )
        offset -= dash
        legend.append(
            f'<span><i class="legend-dot donut-bg-{html.escape(class_name)}"></i>'
            f'<b>{html.escape(str(value))}</b> {html.escape(label)}</span>'
        )
    return f'''
    <article class="exec-card chart-card">
      <div class="exec-card-title"><span>{html.escape(title)}</span><b>{html.escape(subtitle)}</b></div>
      <div class="donut-layout">
        <div class="donut-wrap">
          <svg class="donut-chart" viewBox="0 0 36 36" role="img" aria-label="{html.escape(title)}">
            <circle class="donut-track" cx="18" cy="18" r="15.915"></circle>
            {''.join(segments)}
          </svg>
          <div class="donut-center">{html.escape(center)}</div>
        </div>
        <div class="donut-legend">{''.join(legend)}</div>
      </div>
    </article>'''


def executive_bar_card(title: str, subtitle: str, rows: list[tuple[str, int]], suffix: str = '') -> str:
    max_value = max((value for _label, value in rows), default=0)
    if not rows:
        rows = [('No data', 0)]
    bars = []
    for label, value in rows:
        width = pct(value, max_value) if max_value else 0
        bars.append(
            f'<div class="exec-bar-row"><div class="exec-bar-label" title="{html.escape(label, quote=True)}">{html.escape(label)}</div>'
            f'<div class="exec-bar-track"><span style="width:{width}%"></span></div>'
            f'<div class="exec-bar-value">{html.escape(str(value))}{html.escape(suffix)}</div></div>'
        )
    return f'''
    <article class="exec-card bar-card">
      <div class="exec-card-title"><span>{html.escape(title)}</span><b>{html.escape(subtitle)}</b></div>
      <div class="exec-bars">{''.join(bars)}</div>
    </article>'''


def executive_home_section(reports: list[AlertReport]) -> str:
    """Render executive-level summary metrics for the Home page."""
    total_groups = len(reports)
    total_observations = sum(max(1, int(report.repeat_count or 1)) for report in reports)
    urgent_groups = sum(1 for report in reports if criticality_class(report.criticality) in {'critical', 'high'})
    suppressed_groups = sum(1 for report in reports if report.filter_status == 'suppressed')
    analyzed_groups = sum(1 for report in reports if report.ai_status_key == 'analyzed')
    latest_seen = max((report.alert_ts for report in reports), default=0)
    latest_seen_text = human_time(latest_seen) if latest_seen else 'n/a'

    severity_order = [
        ('Critical', 'critical'),
        ('High', 'high'),
        ('Medium', 'medium'),
        ('Low', 'low'),
        ('Info', 'informational'),
    ]
    severity_counts = {
        level: sum(1 for report in reports if criticality_class(report.criticality) == level)
        for _label, level in severity_order
    }
    severity_rows = [(label, severity_counts[level], level) for label, level in severity_order]

    status_order = [('Accepted', 'accepted'), ('Suppressed', 'suppressed'), ('Escalated', 'escalated'), ('Stored', 'stored'), ('Other', 'other')]
    status_counts = {key: 0 for _label, key in status_order}
    for report in reports:
        key = report.filter_status if report.filter_status in status_counts else 'other'
        status_counts[key] += 1
    status_rows = [(label, status_counts[key], key) for label, key in status_order]

    ai_rows = [
        ('Analyzed', sum(1 for report in reports if report.ai_status_key == 'analyzed'), 'cyan'),
        ('Queued', sum(1 for report in reports if report.ai_status_key == 'queued'), 'amber'),
        ('Analyzing', sum(1 for report in reports if report.ai_status_key == 'analyzing'), 'green'),
        ('Other', sum(1 for report in reports if report.ai_status_key not in {'analyzed', 'queued', 'analyzing'}), 'info'),
    ]

    source_rows = [(label, count) for label, count in counter_top([(report.alert_source, 1) for report in reports], 5)]
    top_rule_rows = counter_top([(report.rule_name, report.repeat_count) for report in reports], 7)
    destination_rows = counter_top([(report.destination_ip, report.repeat_count) for report in reports], 7)
    source_ip_rows = counter_top([(report.source_ip, report.repeat_count) for report in reports], 7)

    now_ts = dt.datetime.now(dt.timezone.utc).timestamp()
    hour_buckets: list[tuple[str, int]] = []
    for hours_ago in range(11, -1, -1):
        bucket_end = now_ts - (hours_ago * 3600)
        bucket_start = bucket_end - 3600
        count = sum(report.repeat_count for report in reports if bucket_start <= report.alert_ts < bucket_end)
        label_time = dt.datetime.fromtimestamp(bucket_start, dt.timezone.utc).strftime('%HZ')
        hour_buckets.append((label_time, count))

    urgent_pct = pct(urgent_groups, total_groups)
    ai_pct = pct(analyzed_groups, total_groups)
    suppression_pct = pct(suppressed_groups, total_groups)

    return f'''
    <section class="view-section active executive-home-view" aria-label="Executive SOC overview">
      <section class="exec-hero" aria-label="Executive SOC summary">
        <div>
          <span class="exec-kicker">Executive overview</span>
          <h2>Security posture at a glance</h2>
          <p>Grouped detections, alert volume, AI analysis coverage, and noisy-repeat pressure from the Security Onion alert pipeline.</p>
        </div>
        <div class="exec-hero-stamp">
          <span>Latest alert</span>
          <strong>{html.escape(latest_seen_text)}</strong>
        </div>
      </section>
      <section class="exec-kpi-grid" aria-label="Executive SOC key metrics">
        <article class="exec-kpi"><span>Grouped detections</span><strong>{total_groups}</strong><em>Unique analyst-facing rows</em></article>
        <article class="exec-kpi"><span>Total observations</span><strong>{total_observations}</strong><em>Includes repeated detections</em></article>
        <article class="exec-kpi"><span>Urgent exposure</span><strong>{urgent_pct}%</strong><em>{urgent_groups} critical/high groups</em></article>
        <article class="exec-kpi"><span>AI coverage</span><strong>{ai_pct}%</strong><em>{analyzed_groups} analyzed groups</em></article>
        <article class="exec-kpi"><span>Suppression pressure</span><strong>{suppression_pct}%</strong><em>{suppressed_groups} noisy groups</em></article>
      </section>
      <section class="exec-chart-grid" aria-label="Executive SOC charts">
        {executive_donut('Severity mix', f'{urgent_pct}%', 'Critical/high share', severity_rows)}
        {executive_donut('Workflow status', f'{suppression_pct}%', 'Suppressed share', status_rows)}
        {executive_donut('AI analysis coverage', f'{ai_pct}%', 'Analyzed share', ai_rows)}
        {executive_bar_card('Top detection families', 'By total observations', top_rule_rows)}
        {executive_bar_card('Top destination assets', 'By total observations', destination_rows)}
        {executive_bar_card('Top source assets', 'By total observations', source_ip_rows)}
        {executive_bar_card('Recent volume', 'Last 12 hours by UTC hour', hour_buckets)}
        {executive_bar_card('Log source mix', 'Grouped detections', source_rows)}
      </section>
    </section>'''


def write_status_json(reports: list[AlertReport]) -> Path:
    """Write the fast-changing status payload polled by the static WebUI."""
    state = ai_activity_state(reports)
    payload = {
        'generated_at': format_project_timestamp(dt.datetime.now(dt.timezone.utc).replace(microsecond=0)),
        'poll_interval_ms': 5000,
        'ai': state,
        'reports': {
            report.digest: {
                'ai_status_key': report.ai_status_key,
                'ai_status_label': report.ai_status_label,
                'ai_status_detail': report.ai_status_detail,
            }
            for report in reports
        },
    }
    STATUS_JSON.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return STATUS_JSON


def write_n8n_beacon_json(reports: list[AlertReport]) -> Path:
    """Seed the dynamic n8n webhook beacon file for static dashboard serving."""
    if DB_BEACON_JSON.exists():
        try:
            payload = json.loads(DB_BEACON_JSON.read_text(encoding='utf-8'))
            N8N_BEACON_JSON.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')
            return N8N_BEACON_JSON
        except Exception:
            pass
    latest_report = max(reports, key=lambda report: report.alert_ts) if reports else None
    payload = {
        'generated_at': iso_local_time(latest_report.alert_ts) if latest_report else format_project_timestamp(dt.datetime.now(dt.timezone.utc).replace(microsecond=0)),
        'stage': 'seeded',
        'ok': True,
        'status': 'seeded_from_dashboard',
        'alert_id': latest_report.rule_id if latest_report else None,
        'rule_name': latest_report.rule_name if latest_report else None,
        'source_ip': latest_report.source_ip if latest_report else None,
        'destination_ip': latest_report.destination_ip if latest_report else None,
        'destination_port': latest_report.destination_port if latest_report else None,
        'triage_level': latest_report.criticality.lower() if latest_report else None,
        'filter_status': None,
        'notification_status': None,
        'error': None,
    }
    N8N_BEACON_JSON.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return N8N_BEACON_JSON


def write_n8n_beacon_history_json() -> Path:
    """Mirror the rolling n8n beacon history into the generated dashboard output."""
    if DB_BEACON_HISTORY_JSON.exists():
        try:
            payload = json.loads(DB_BEACON_HISTORY_JSON.read_text(encoding='utf-8'))
            if isinstance(payload, list):
                N8N_BEACON_HISTORY_JSON.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')
                return N8N_BEACON_HISTORY_JSON
        except Exception:
            pass
    N8N_BEACON_HISTORY_JSON.write_text('[]\n', encoding='utf-8')
    return N8N_BEACON_HISTORY_JSON



def write_detail_fragments(reports: list[AlertReport]) -> list[Path]:
    """Write one lazy-loaded detail fragment per grouped alert row."""
    if DETAIL_DIR.exists():
        shutil.rmtree(DETAIL_DIR)
    DETAIL_DIR.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for report in reports:
        if not re.fullmatch(r'[a-f0-9]{12}', report.digest):
            continue
        path = DETAIL_DIR / f'{report.digest}.html'
        body = f'<div class="markdown-body">{report.rendered_html}</div>\n'
        path.write_text(body, encoding='utf-8')
        written.append(path)
    return written


def build_html(reports: list[AlertReport]) -> str:
    # Preserve the existing LAN Portal UI while swapping the data source behind
    # it. The next scale step is to replace this full-page render with paginated
    # API calls.
    now = dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace('T', '  ')
    latest = reports[0] if reports else None
    active_count = active_alert_count(reports)
    total_bytes = sum(r.size for r in reports)
    pcap_ingest_bytes = directory_size_bytes(PCAP_ARTIFACT_DIR)
    latest_text = human_time(latest.mtime) if latest else 'No reports yet'
    last_workflow_trigger = max(reports, key=lambda report: report.alert_ts) if reports else None
    workflow_trigger_text = human_time(last_workflow_trigger.alert_ts) if last_workflow_trigger else 'No triggers yet'
    workflow_trigger_extra_html = (
        f'<span class="metric-detail-row"><b>Alert</b><span>{html.escape(last_workflow_trigger.title)}</span></span>'
        f'<span class="metric-detail-row"><b>Source</b><span>{html.escape(last_workflow_trigger.rel_source)}</span></span>'
    ) if last_workflow_trigger else '<span class="metric-detail-row"><b>Alert</b><span>—</span></span>'
    active_reports = active_alert_reports(reports)
    severity_levels = ['critical', 'high', 'medium', 'low', 'informational']
    severity_labels = {'critical': 'Crit', 'high': 'High', 'medium': 'Med', 'low': 'Low', 'informational': 'Info'}
    total_severity_counts = {level: 0 for level in severity_levels}
    for report in active_reports:
        total_severity_counts[criticality_class(report.criticality)] = total_severity_counts.get(criticality_class(report.criticality), 0) + 1
    total_severity_html = ''.join(
        f'<span class="sev-chip sev-{level}{" sev-zero" if total_severity_counts[level] == 0 else ""}"><b>{total_severity_counts[level]}</b> {severity_labels[level]}</span>'
        for level in severity_levels
    )
    latest_extra_html = (
        f'<span class="metric-detail-row"><b>Source</b><span>{html.escape(latest.rel_source)}</span></span>'
        f'<span class="metric-detail-row"><b>Size</b><span>{human_size(latest.size)}</span></span>'
    ) if latest else '<span class="metric-detail-row"><b>Source</b><span>—</span></span>'
    latest_alert = max(reports, key=last_seen_ts_for) if reports else None
    latest_alert_text = compact_minute_timestamp(last_seen_iso_for(latest_alert)) if latest_alert else 'No alerts yet'
    ai_state = ai_activity_state(reports)
    soc_metrics_html = ''.join(
        [
            render_active_alerts_metric(total_severity_html),
            render_latest_network_metric(latest_extra_html),
            render_ai_activity_metric(ai_state),
            render_alert_status_metric(),
            render_size_metric_card(human_size(total_bytes), latest_alert_text, human_size(pcap_ingest_bytes)),
        ]
    )
    first = reports[0] if reports else None
    repeat_next_minutes_by_digest: dict[str, int] = {}
    reports_by_rule: dict[str, list[AlertReport]] = {}
    for report in reports:
        rule_key = report.rule_id if report.rule_id != '—' else report.rule_name.lower()
        reports_by_rule.setdefault(rule_key, []).append(report)
    for same_rule_reports in reports_by_rule.values():
        ordered = sorted(same_rule_reports, key=lambda report: report.alert_ts)
        for current, next_report in zip(ordered, ordered[1:]):
            delta_minutes = max(0, round((next_report.alert_ts - current.alert_ts) / 60))
            repeat_next_minutes_by_digest[current.digest] = delta_minutes
    report_rows = '\n'.join(
        f'''
        <tbody class="report-row-group" data-report-id="{html.escape(r.digest)}" data-title="{html.escape(r.title.lower())}" data-source="{html.escape(r.rel_source.lower())}" data-body="{html.escape((r.criticality + ' ' + r.summary + ' ' + ai_summary_for(r) + ' ' + r.alert_source + ' ' + r.source_ip + ' ' + r.destination_ip + ' ' + r.destination_port + ' ' + r.rule_id + ' ' + r.rule_name + ' ' + r.alert_group_key + ' ' + str(r.repeat_count) + ' ' + r.ai_status_label + ' ' + r.enrichment_status_label + ' ' + r.pcap_status_label).lower())}" data-alert-group-key="{html.escape(r.alert_group_key)}" data-repeat-count="{r.repeat_count}" data-criticality="{html.escape(r.criticality.lower())}" data-ai-status="{html.escape(r.ai_status_key)}" data-enrichment-status="{html.escape(r.enrichment_status_key)}" data-pcap-status="{html.escape(r.pcap_status_key)}" data-risk-score="{risk_score_for(r)}" data-mtime="{int(last_seen_ts_for(r))}" data-alert-ts="{int(r.alert_ts)}" data-rule-id="{html.escape(r.rule_id, quote=True)}" data-rule-name="{html.escape(r.rule_name, quote=True)}" data-alert-source="{html.escape(r.alert_source, quote=True)}" data-source-ip="{html.escape(r.source_ip, quote=True)}" data-destination-ip="{html.escape(r.destination_ip, quote=True)}" data-destination-port="{html.escape(r.destination_port, quote=True)}" data-suppressed-next-minutes="{repeat_next_minutes_by_digest.get(r.digest, '')}" data-summary="{html.escape(ai_summary_for(r), quote=True)}" data-modified="{html.escape(last_seen_iso_for(r), quote=True)}" data-size="{human_size(r.size)}" data-size-bytes="{r.size}" data-source-label="{html.escape(r.rel_source, quote=True)}" data-acknowledged="false" data-suppressed="false">
          <tr class="report-row" tabindex="0" aria-selected="false">
            <td class="select-cell"><span class="row-check">✓</span></td>
            <td class="endpoint-cell count-cell"><span class="alert-repeat-count">{r.repeat_count}</span></td>
            <td class="severity-cell"><span class="severity-label severity-text-{html.escape(criticality_class(r.criticality))}">{html.escape(r.criticality)}</span></td>
            <td class="last-seen-cell" data-last-seen-utc="{html.escape(last_seen_iso_for(r), quote=True)}">{html.escape(last_seen_iso_for(r))}</td>
            <td class="alert-cell"><strong>{html.escape(r.title)}</strong></td>
            <td class="endpoint-cell ip-cell"><code>{html.escape(r.source_ip)}</code></td>
            <td class="endpoint-cell ip-cell"><code>{html.escape(r.destination_ip)}</code></td>
            <td class="endpoint-cell port-cell"><code>{html.escape(r.destination_port)}</code></td>
            <td class="ai-status-cell">{ai_status_pill(r)}</td>
            <td class="enrichment-status-cell">{enrichment_status_pill(r)}</td>
            <td class="pcap-status-cell">{pcap_status_pill(r)}</td>
            <td class="source-cell"><code>{html.escape(r.alert_source)}</code></td>
            <td>{human_size(r.size)}</td><td class="wide-only">{risk_score_for(r)}</td>
            <td class="action-cell"><button class="ack-button" type="button" data-acknowledge="{html.escape(r.digest)}">Acknowledge</button><button class="ack-button suppress-button" type="button" data-suppress="{html.escape(r.digest)}">Suppress</button></td><td class="menu-cell">⋮</td>
          </tr><tr class="detail-template-row"><td colspan="16"><div class="detail-template"><div class="detail-label">Detailed Alert Report</div><div class="suppression-note" hidden><h3>Suppression Note</h3><p class="suppression-note-text"></p><small class="suppression-note-meta"></small></div><div class="markdown-body">{r.rendered_html}</div></div></td></tr>
        </tbody>'''
        for r in reports
    )
    mobile_cards = '\n'.join(
        f'''
        <article class="mobile-alert-card" data-mobile-report-id="{html.escape(r.digest)}" data-acknowledged="false" data-suppressed="false" data-rule-id="{html.escape(r.rule_id, quote=True)}" data-rule-name="{html.escape(r.rule_name, quote=True)}" data-suppressed-next-minutes="{repeat_next_minutes_by_digest.get(r.digest, '')}">
          <button class="mobile-alert-pill" type="button" aria-expanded="false" aria-controls="mobile-detail-{html.escape(r.digest)}">
            <span class="mobile-card-top"><span class="severity-label severity-text-{html.escape(criticality_class(r.criticality))}">{html.escape(r.criticality)}</span><span class="mobile-card-time">Last Seen <span data-last-seen-utc="{html.escape(last_seen_iso_for(r), quote=True)}">{html.escape(last_seen_iso_for(r))}</span></span></span>
            <strong>{html.escape(r.title)}</strong>
            <span class="mobile-card-summary">{html.escape(ai_summary_for(r))}</span>
            <span class="mobile-endpoints"><span><b>Src</b><code>{html.escape(r.source_ip)}:{html.escape(r.source_port)}</code></span><span><b>Dst</b><code>{html.escape(r.destination_ip)}:{html.escape(r.destination_port)}</code></span></span>
            <span class="mobile-card-meta"><span>Count <b>{r.repeat_count}</b></span><span>Risk <b>{risk_score_for(r)}</b></span><span>{ai_status_pill(r)}</span><span>{enrichment_status_pill(r)}</span><span>{pcap_status_pill(r)}</span><span>{human_size(r.size)}</span></span>
          </button>
          <div id="mobile-detail-{html.escape(r.digest)}" class="mobile-pill-details" hidden>
            <div class="mobile-card-actions"><button class="ack-button" type="button" data-acknowledge="{html.escape(r.digest)}">Acknowledge</button><button class="ack-button suppress-button" type="button" data-suppress="{html.escape(r.digest)}">Suppress</button></div>
            <div class="suppression-note" hidden><h3>Suppression Note</h3><p class="suppression-note-text"></p><small class="suppression-note-meta"></small></div>
            <div class="markdown-body">{r.rendered_html}</div>
          </div>
        </article>'''
        for r in reports
    )
    mobile_triage_controls = '''<div class="mobile-triage-bar" aria-label="Mobile alert triage controls"><div class="severity-chip-row"><button class="severity-chip active" type="button" data-severity-filter="all">All</button><button class="severity-chip sev-critical" type="button" data-severity-filter="critical">Critical</button><button class="severity-chip sev-high" type="button" data-severity-filter="high">High</button><button class="severity-chip sev-medium" type="button" data-severity-filter="medium">Medium</button><button class="severity-chip sev-low" type="button" data-severity-filter="low">Low</button><button class="severity-chip sev-informational" type="button" data-severity-filter="informational">Info</button></div><label class="mobile-sort-label">Sort <select id="mobile-sort"><option value="priority">Priority</option><option value="newest">Newest</option><option value="risk">Risk score</option></select></label></div>'''
    table_html = f'''{mobile_triage_controls}<div class="mobile-alert-list" aria-label="Mobile SOC alert cards"></div><div class="table-card"><table class="alert-table"><thead><tr><th></th><th><button class="sort-header" type="button" data-sort-key="count">Count<span class="sort-indicator"></span></button></th><th class="severity-header"><button class="sort-header" type="button" data-sort-key="severity">Severity<span class="sort-indicator"></span></button></th><th><button class="sort-header" type="button" data-sort-key="last_seen">Last Seen<span class="sort-indicator"></span></button></th><th><button class="sort-header" type="button" data-sort-key="alert">Alert<span class="sort-indicator"></span></button></th><th class="ip-header"><button class="sort-header" type="button" data-sort-key="source_ip">Source IP<span class="sort-indicator"></span></button></th><th class="ip-header"><button class="sort-header" type="button" data-sort-key="destination_ip">Destination IP<span class="sort-indicator"></span></button></th><th class="port-header"><button class="sort-header" type="button" data-sort-key="destination_port">Destination Port<span class="sort-indicator"></span></button></th><th class="ai-header"><button class="sort-header" type="button" data-sort-key="ai">AI<span class="sort-indicator"></span></button></th><th class="enrichment-header"><button class="sort-header" type="button" data-sort-key="enrichment">Enrichment<span class="sort-indicator"></span></button></th><th class="pcap-header"><button class="sort-header" type="button" data-sort-key="pcap">PCAP<span class="sort-indicator"></span></button></th><th><button class="sort-header" type="button" data-sort-key="log_source">Log Source<span class="sort-indicator"></span></button></th><th><button class="sort-header" type="button" data-sort-key="size">Size<span class="sort-indicator"></span></button></th><th class="wide-only"><button class="sort-header" type="button" data-sort-key="risk">Risk<span class="sort-indicator"></span></button></th><th>Action</th><th></th></tr></thead></table><div class="api-pagination"><div class="api-page-size"><span>Rows</span><select id="api-page-size" aria-label="Rows per page"><option value="25" selected>25</option><option value="50">50</option><option value="75">75</option><option value="100">100</option><option value="250">250</option></select></div><div class="api-page-controls" aria-label="Alert table pagination"><button id="api-prev-page" class="ack-button api-page-button" type="button">Previous</button><select id="api-page-select" aria-label="Alert table page"><option value="1">Page 1</option></select><button id="api-next-page" class="ack-button api-page-button" type="button">Next</button></div><span id="api-alert-page-status" class="api-page-status">Loading alerts from SQLite API...</span><div class="api-table-metrics" aria-label="Alert table totals"><span class="api-table-metric"><b id="api-visible-total">0</b> Active</span><span class="api-table-metric suppressed"><b id="api-suppressed-total">0</b> Suppressed</span><span class="api-table-metric acknowledged"><b id="api-acknowledged-total">0</b> Acknowledged</span></div></div></div>'''
    overview_html = f'''
    <section id="overview-view" class="view-section overview-view" aria-label="SOC Alerts overview">
      <div class="overview-grid">
        <section class="flow-hero" aria-label="Autonomous SIEM alert enrichment data flow">
          <div class="flow-copy">
            <span class="flow-kicker">Network flow</span>
            <h2>Autonomous SIEM Alert Enrichment & Threat Investigation</h2>
            <p>Alerts are pulled from Security Onion by the isolated relay, scored on the Mac Studio, stored in SQLite, then fanned out to the dashboard, Markdown reports, local AI context, and Telegram.</p>
          </div>
          <div class="network-diagram" role="img" aria-label="Security Onion alert data flow diagram">
            <div class="flow-node node-so">
              <span class="node-icon">SO</span>
              <strong>Security Onion</strong>
              <span class="flow-ip-address" data-ip="192.168.1.7">xxx.xxx.xxx.xxx</span>
              <em>Alert source</em>
            </div>
            <div class="flow-link link-one"><span>restricted SSH poll</span></div>
            <div class="flow-node node-pi">
              <span class="node-icon">Pi</span>
              <strong>Relay VLAN 888</strong>
              <span class="flow-ip-address" data-ip="10.88.8.8">xxx.xxx.xxx.xxx</span>
              <em>Transport only</em>
            </div>
            <div class="flow-link link-two"><span>webhook POST</span></div>
            <div class="flow-node node-mac">
              <span class="node-icon">AI</span>
              <strong>Mac Studio AI Lab</strong>
              <span class="flow-ip-address" data-ip="10.77.7.225">xxx.xxx.xxx.xxx</span>
              <em>n8n + SQLite</em>
            </div>
            <div class="flow-fanout" aria-hidden="true"></div>
            <div class="flow-output output-dashboard"><b>Dashboard</b><span>Grouped Count rows</span></div>
            <div class="flow-output output-markdown"><b>Markdown</b><span>Reports + rollups</span></div>
            <div class="flow-output output-ai"><b>Local AI</b><span>Prompt packages</span></div>
            <div class="flow-output output-phone"><b>Telegram</b><span>High/critical only</span></div>
          </div>
        </section>
        <section class="overview-status" aria-label="Pipeline status">
          <div class="status-tile"><span>Source</span><strong>Security Onion</strong><em>Restricted export wrapper</em></div>
          <div class="status-tile"><span>Relay</span><strong>Raspberry Pi</strong><em>5 minute timer</em></div>
          <div class="status-tile"><span>Store</span><strong>SQLite</strong><em>{len(reports)} grouped detections</em></div>
          <div class="status-tile"><span>Analyst</span><strong>Local AI</strong><em>Daily rollups ready</em></div>
        </section>
      </div>
    </section>'''
    flow_html = f'''
    <section id="overview-view" class="view-section overview-view flow-page-view" aria-label="Autonomous SIEM alert enrichment data flow">
      <section class="flow-product-hero" aria-labelledby="flow-title">
        <button class="flow-privacy-toggle" type="button" aria-pressed="false" aria-label="Show node IP addresses" title="Show node IP addresses">
          <img src="assets/privacy-eye-button.png" alt="" aria-hidden="true">
        </button>
        <div class="flow-product-copy">
          <h2 id="flow-title">Autonomous SIEM Alert Enrichment & Threat Investigation</h2>
          <div class="flow-pulse-divider" aria-hidden="true"></div>
          <p>Alerts move through an isolated relay, into a containerized n8n workflow, then into the Mac Studio analysis plane for SQLite storage, Markdown reports, local AI context, and high-signal Telegram notifications.</p>
        </div>
        <div class="flow-product-map" role="img" aria-label="Animated Security Onion alert pipeline">
          <div class="flow-spine" aria-hidden="true">
            <span class="flow-packet packet-one"></span>
            <span class="flow-packet packet-two"></span>
            <span class="flow-packet packet-three"></span>
          </div>
          <article class="flow-system-node node-security-onion">
            <span class="flow-logo-ring"><img src="assets/brand/security-onion.svg" alt="Security Onion logo"></span>
            <div><strong>Security Onion</strong><span class="flow-ip-address" data-ip="192.168.1.7">xxx.xxx.xxx.xxx</span></div>
            <em>Alert source</em>
          </article>
          <div class="flow-connector connector-one"><span>restricted SSH poll</span></div>
          <article class="flow-system-node node-raspberry-pi">
            <span class="flow-logo-ring"><img src="assets/brand/raspberry-pi.svg" alt="Raspberry Pi logo"></span>
            <div><strong>Raspberry Pi Relay</strong><span class="flow-ip-address" data-ip="10.88.8.8">xxx.xxx.xxx.xxx</span></div>
            <em>VLAN 888 transport</em>
          </article>
          <div class="flow-connector connector-two"><span>webhook POST</span></div>
          <article class="flow-system-node node-docker">
            <span class="flow-logo-ring"><img src="assets/brand/docker.svg" alt="Docker logo"></span>
            <div><strong>Docker</strong><span class="flow-ip-address" data-ip="10.77.7.225">xxx.xxx.xxx.xxx</span></div>
            <em>Container runtime</em>
          </article>
          <div class="flow-connector connector-three"><span>container network</span></div>
          <article class="flow-system-node node-n8n">
            <span class="flow-logo-ring"><img src="assets/brand/n8n.svg" alt="n8n logo"></span>
            <div><strong>n8n Workflow</strong><span>:5678 webhook</span></div>
            <em>Scoring + routing</em>
          </article>
          <div class="flow-connector connector-four"><span>write + analyze</span></div>
          <article class="flow-system-node node-mac">
            <span class="flow-logo-ring"><img src="assets/brand/apple.svg" alt="Apple logo"></span>
            <div><strong>Mac Studio AI Lab</strong><span class="flow-ip-address" data-ip="10.77.7.225">xxx.xxx.xxx.xxx</span></div>
            <em>SQLite + local AI</em>
          </article>
          <div class="flow-output-grid">
            <div class="flow-output-card"><b>SQLite</b><span>{len(reports)} grouped detections</span></div>
            <div class="flow-output-card"><b>Markdown</b><span>SOC reports + rollups</span></div>
            <div class="flow-output-card"><b>Local AI</b><span>Prompt packages + analysis</span></div>
            <div class="flow-output-card"><b>Telegram</b><span>High and critical alerts</span></div>
          </div>
        </div>
      </section>
      <section class="flow-summary-grid" aria-label="Pipeline service summary">
        <div class="flow-summary-card"><span>Source</span><strong>Security Onion</strong><em>Restricted export wrapper</em></div>
        <div class="flow-summary-card"><span>Relay</span><strong>Raspberry Pi</strong><em>5 minute timer</em></div>
        <div class="flow-summary-card"><span>Runtime</span><strong>Docker</strong><em>n8n container</em></div>
        <div class="flow-summary-card"><span>Workflow</span><strong>n8n</strong><em>Scoring, storage, notify</em></div>
        <div class="flow-summary-card"><span>Analyst plane</span><strong>Mac Studio</strong><em>SQLite, Markdown, local AI</em></div>
      </section>
    </section>'''
    selected_title = html.escape(first.title) if first else 'No alert selected'
    selected_summary = html.escape(ai_summary_for(first)) if first else 'Select an alert to inspect its generated report.'
    selected_criticality = html.escape(first.criticality) if first else '—'
    selected_criticality_class = criticality_class(first.criticality) if first else 'informational'
    selected_score = risk_score_for(first) if first else 0
    selected_modified = html.escape(human_time(first.mtime)) if first else '—'
    selected_size = human_size(first.size) if first else '—'
    selected_source = html.escape(first.rel_source) if first else '—'
    selected_body = first.rendered_html if first else '<p>No report selected.</p>'
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>SOC Alerts</title><link rel="icon" type="image/png" href="assets/onion-sentinel-logo.png"/><link rel="apple-touch-icon" href="assets/onion-sentinel-logo.png"/><style>
.suppression-network-context{{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin:-2px 0 10px;padding:0 2px;max-width:100%;color:#c8d5e4;font:12px/1.35 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;overflow-wrap:anywhere}}
.suppression-network-context::before{{content:"Route";flex:0 0 auto;border:1px solid rgba(34,211,238,.24);border-radius:999px;padding:2px 7px;color:#8ff4ff;font:10px/1 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-weight:950;text-transform:uppercase;letter-spacing:.08em}}
.suppression-network-context[hidden]{{display:none!important}}
.alert-timeline-pagination{{display:flex;align-items:center;justify-content:flex-end;gap:10px;margin:10px 0 0;color:#91a4ba;font-size:12px;font-weight:800;flex-wrap:wrap}}
.timeline-page-button{{border:1px solid rgba(34,211,238,.22);border-radius:8px;padding:7px 10px;color:#dce9f8;background:#0b131c;font-size:12px;font-weight:850;cursor:pointer}}
.timeline-page-button:hover:not(:disabled){{border-color:rgba(34,211,238,.52);color:#8ff4ff}}
.timeline-page-button:disabled{{opacity:.42;cursor:not-allowed}}
.alert-status-card{{align-items:center!important;justify-content:center!important;gap:0!important;padding:14px!important;overflow:hidden!important}}
.alert-status-card .metric-icon{{display:none!important}}
.alert-status-main{{min-width:0!important;flex:0 1 auto!important}}
.alert-status-main strong{{font-size:15px!important;line-height:1.1!important;white-space:nowrap!important}}
.alert-status-metrics{{display:grid!important;grid-template-columns:repeat(2,max-content)!important;justify-content:start!important;gap:8px 16px!important;margin:10px 0 0!important}}
.alert-status-metrics .api-table-metric{{display:inline-flex!important;align-items:baseline!important;gap:5px!important;width:auto!important;min-width:0!important;justify-content:flex-start!important;border:0!important;border-radius:0!important;padding:0!important;color:#9fb0c4!important;background:transparent!important;box-shadow:none!important;font-size:11px!important;line-height:1!important}}
px!important;line-height:1!important;color:#8ff4ff!important}}
.alert-status-metrics .api-table-metric.total b{{color:#eef8ff!important}}
.alert-status-metrics .api-table-metric.suppressed b{{color:#fb7185!important}}
.alert-status-metrics .api-table-metric.acknowledged b{{color:#f6c76d!important}}
.severity-summary-card{{align-items:center!important;justify-content:center!important;gap:0!important;padding:14px!important}}
.severity-summary-card .metric-icon{{display:none!important}}
.severity-summary-main{{min-width:0!important;flex:0 1 auto!important}}
.severity-summary-main,.alert-status-main{{width:min(100%,252px)!important;flex-basis:252px!important}}
.severity-summary-card,.alert-status-card{{align-items:flex-start!important}}
.severity-summary-main strong,.alert-status-main strong{{display:block!important;font-size:18px!important;line-height:1.1!important;letter-spacing:-.02em!important;text-align:left!important}}
.severity-card-counts,.alert-status-metrics{{display:grid!important;grid-template-columns:70px 132px!important;justify-content:start!important;align-items:baseline!important;gap:8px 14px!important;margin:12px 0 0!important}}
.severity-card-counts .sev-chip,.alert-status-metrics .api-table-metric{{display:inline-flex!important;align-items:baseline!important;gap:5px!important;min-width:0!important;width:auto!important;justify-content:flex-start!important;color:#9fb0c4!important;font-size:12px!important;line-height:1!important;white-space:nowrap!important}}
px!important;line-height:1!important;letter-spacing:0!important}}
.alert-status-metrics{{grid-template-columns:70px minmax(0,1fr)!important;gap:9px 18px!important}}
.alert-status-metrics .api-table-metric.acknowledged,.alert-status-metrics .api-table-metric.suppressed{{grid-column:1/-1!important}}
.latest-network-card{{align-items:flex-start!important;justify-content:center!important;gap:0!important;padding:14px!important;overflow:hidden!important}}
.latest-network-card .metric-icon,.latest-network-card .metric-extra{{display:none!important}}
.latest-network-main{{width:min(100%,252px)!important;flex:0 1 252px!important;min-width:0!important}}
.latest-network-main strong{{display:block!important;font-size:18px!important;line-height:1.1!important;letter-spacing:-.02em!important;text-align:left!important}}
.latest-network-metrics{{display:grid!important;grid-template-columns:minmax(0,1fr)!important;gap:9px!important;margin:14px 0 0!important}}
.latest-network-metric{{display:flex!important;align-items:baseline!important;gap:8px!important;min-width:0!important;color:#9fb0c4!important;font-size:12px!important;font-weight:850!important;line-height:1!important;white-space:nowrap!important}}
.latest-network-metric span{{flex:0 0 auto!important;color:#9fb0c4!important}}
.latest-network-metric b{{min-width:0!important;overflow:hidden!important;text-overflow:ellipsis!important;color:#eef8ff!important;font:700 18px/1 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace!important;letter-spacing:0!important}}
.latest-network-metric{{display:flex!important;grid-template-columns:none!important;align-items:baseline!important;gap:6px!important}}
.latest-network-metric span{{font-size:11px!important;line-height:1!important;text-transform:none!important}}
.latest-network-metric b{{display:inline-block!important;width:auto!important;min-width:0!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important;font-size:13px!important}}
:root{{--sticky-row-top:92px;--bg:#071018;--sidebar:#0b141d;--panel:#0d1620;--panel2:#101923;--line:rgba(148,163,184,.13);--text:#e8f1fb;--muted:#8d9cad;--cyan:#22d3ee;--green:#22c55e;--amber:#f6c76d;--red:#fb7185;--orange:#fb923c}}*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#071018}}.app-shell{{display:grid;grid-template-columns:220px minmax(0,1fr);min-height:100vh;transition:grid-template-columns .18s ease}}.app-shell.sidebar-collapsed{{grid-template-columns:72px minmax(0,1fr)}}.sidebar{{position:sticky;top:0;height:100vh;max-height:100vh;display:flex;flex-direction:column;gap:18px;overflow-y:auto;overscroll-behavior:contain;scrollbar-width:thin;scrollbar-color:rgba(34,211,238,.36) rgba(7,16,24,.38);padding:22px 16px;border-right:1px solid rgba(148,163,184,.10);background:linear-gradient(180deg,#0b141d,#09111a);transition:padding .18s ease}}.sidebar::-webkit-scrollbar{{width:8px}}.sidebar::-webkit-scrollbar-track{{background:rgba(7,16,24,.34)}}.sidebar::-webkit-scrollbar-thumb{{border:2px solid rgba(7,16,24,.34);border-radius:999px;background:rgba(34,211,238,.32)}}.sidebar::-webkit-scrollbar-thumb:hover{{background:rgba(143,244,255,.52)}}.brand{{display:flex;align-items:center;gap:9px;font-weight:900;font-size:18px;letter-spacing:-.03em}}.brand-shield{{width:44px;height:44px;display:grid;place-items:center;flex:0 0 44px;color:#8ff4ff}}.logo-toggle{{padding:0;border:1px solid transparent;border-radius:12px;background:transparent;cursor:pointer;transition:border-color .14s ease,background .14s ease,box-shadow .14s ease,transform .14s ease}}.logo-toggle:hover{{border-color:rgba(34,211,238,.40);background:rgba(34,211,238,.08);box-shadow:0 0 0 1px rgba(34,211,238,.10),0 0 18px rgba(34,211,238,.18)}}.logo-toggle:focus-visible{{outline:2px solid rgba(34,211,238,.70);outline-offset:3px}}.brand-logo{{width:44px;height:44px;filter:drop-shadow(0 0 10px rgba(34,211,238,.18));pointer-events:none}}.logo-toggle:hover .brand-logo{{filter:drop-shadow(0 0 12px rgba(34,211,238,.42))}}.brand span span{{color:var(--cyan)}}.brand-text,.nav-label,.nav-count,.health,.analyst{{transition:opacity .14s ease,transform .14s ease}}.nav{{display:grid;gap:4px;margin-top:14px}}.nav-item{{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 11px;border:1px solid transparent;border-radius:10px;color:#aeb9c7;font-size:13px;font-weight:750;text-decoration:none;white-space:nowrap}}.nav-left{{display:flex;align-items:center;gap:10px;min-width:0}}.nav-icon{{width:24px;height:24px;display:inline-grid;place-items:center;flex:0 0 24px;color:#aeb9c7}}.nav-icon svg{{width:24px;height:24px;stroke:currentColor;fill:none;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round}}.nav-item:hover{{border-color:rgba(34,211,238,.40);color:#8ff4ff;background:rgba(34,211,238,.08);box-shadow:0 0 0 1px rgba(34,211,238,.10),0 0 18px rgba(34,211,238,.18)}}.nav-item:hover .nav-icon,.nav-item.active .nav-icon{{color:#8ff4ff;filter:drop-shadow(0 0 7px rgba(34,211,238,.45))}}.nav-item.active{{box-shadow:0 0 0 1px rgba(34,211,238,.16),0 0 22px rgba(34,211,238,.22)}}.nav-label{{overflow:hidden;text-overflow:ellipsis}}.nav-item.active{{color:#eff7ff;background:rgba(34,211,238,.08);border:1px solid rgba(34,211,238,.14)}}.nav-count{{--nav-count-color:#8ff4ff;--nav-count-border:rgba(34,211,238,.18);--nav-count-bg:rgba(34,211,238,.08);color:var(--nav-count-color);border:1px solid var(--nav-count-border);border-radius:999px;padding:2px 7px;font-size:11px;background:var(--nav-count-bg);box-shadow:0 0 12px color-mix(in srgb,var(--nav-count-color) 18%,transparent)}}.nav-count-sev-critical{{--nav-count-color:var(--red);--nav-count-border:rgba(251,113,133,.38);--nav-count-bg:rgba(251,113,133,.10)}}.nav-count-sev-high{{--nav-count-color:var(--orange);--nav-count-border:rgba(251,146,60,.38);--nav-count-bg:rgba(251,146,60,.10)}}.nav-count-sev-medium{{--nav-count-color:var(--amber);--nav-count-border:rgba(246,199,109,.38);--nav-count-bg:rgba(246,199,109,.10)}}.nav-count-sev-low{{--nav-count-color:#86efac;--nav-count-border:rgba(134,239,172,.34);--nav-count-bg:rgba(134,239,172,.08)}}.nav-count-sev-informational,.nav-count-sev-info{{--nav-count-color:#93c5fd;--nav-count-border:rgba(147,197,253,.34);--nav-count-bg:rgba(147,197,253,.08)}}.nav-count-sev-none{{--nav-count-color:#8ff4ff;--nav-count-border:rgba(34,211,238,.18);--nav-count-bg:rgba(34,211,238,.08)}}.app-shell.sidebar-collapsed .sidebar{{padding:22px 10px;align-items:center}}.app-shell.sidebar-collapsed .brand{{width:100%;justify-content:center}}.app-shell.sidebar-collapsed .brand-text,.app-shell.sidebar-collapsed .nav-label,.app-shell.sidebar-collapsed .nav-count,.app-shell.sidebar-collapsed .sidebar-bottom{{display:none}}.app-shell.sidebar-collapsed .logo-toggle{{margin:0}}.app-shell.sidebar-collapsed .nav{{width:100%;margin-top:18px}}.app-shell.sidebar-collapsed .nav-item{{justify-content:center;padding:14px 0}}.app-shell.sidebar-collapsed .nav-left{{justify-content:center;gap:0}}.sidebar-bottom{{margin-top:auto;display:grid;gap:14px}}.health,.analyst{{border:1px solid rgba(148,163,184,.12);border-radius:12px;padding:12px;background:rgba(255,255,255,.025);color:#c9d5e4;font-size:12px}}.health b,.analyst b{{display:block;color:#f4f8ff;margin-bottom:5px}}.byline{{line-height:1.35}}.byline a{{color:var(--cyan);font-weight:900;text-decoration:none}}.byline a:hover{{color:#8ff4ff;text-shadow:0 0 10px rgba(34,211,238,.42)}}.status-dot{{display:inline-block;width:7px;height:7px;border-radius:999px;background:var(--green);margin-right:6px}}.content{{min-width:0;padding:22px}}.topbar{{position:sticky;top:0;z-index:30;display:grid;grid-template-columns:minmax(240px,1fr) minmax(260px,420px) auto auto;gap:16px;align-items:end;padding:0 0 16px;background:linear-gradient(180deg,rgba(7,16,24,.98),rgba(7,16,24,.88),transparent);backdrop-filter:blur(14px)}}.toggle-refresh-group{{display:inline-flex;align-items:end;justify-content:flex-start;gap:14px;min-width:max-content}}.title-row{{display:flex;align-items:center;gap:12px}}.title h1{{margin:0;font-size:30px;letter-spacing:-.045em;line-height:1}}.mobile-controls-toggle{{display:none;align-items:center;justify-content:center;gap:4px;width:40px;height:40px;border:1px solid rgba(34,211,238,.22);border-radius:12px;color:#8ff4ff;background:#0b131c;box-shadow:inset 0 1px 0 rgba(255,255,255,.035);cursor:pointer}}.mobile-controls-toggle span{{display:block;width:17px;height:2px;border-radius:999px;background:currentColor;box-shadow:0 0 8px rgba(34,211,238,.22)}}.mobile-controls-toggle:hover{{border-color:rgba(34,211,238,.48);box-shadow:0 0 16px rgba(34,211,238,.16),inset 0 1px 0 rgba(255,255,255,.045)}}.mobile-controls-toggle:focus-visible{{outline:2px solid rgba(143,244,255,.88);outline-offset:3px}}.mobile-controls-toggle[aria-expanded="true"]{{background:rgba(34,211,238,.10);border-color:rgba(34,211,238,.52)}}.alerts-refresh{{--refresh-accent:#23d3ee;--refresh-glow:rgba(35,211,238,.42);position:relative;flex:0 0 auto;width:44px;height:44px;min-width:44px;min-height:44px;display:inline-flex;align-items:center;justify-content:center;border:1px solid rgba(35,211,238,.56);border-radius:16px;padding:0;color:var(--refresh-accent);background:linear-gradient(145deg,rgba(14,24,38,.78),rgba(7,15,25,.92));box-shadow:0 12px 28px rgba(0,0,0,.26),inset 0 1px 0 rgba(255,255,255,.045),inset 0 -10px 22px rgba(6,12,20,.50);cursor:pointer;transition:transform .16s ease,border-color .16s ease,box-shadow .16s ease,background .16s ease}}.alerts-refresh:before{{content:"";position:absolute;inset:1px;border:1px solid rgba(35,211,238,.18);border-radius:14px;background:radial-gradient(circle at 50% 45%,rgba(35,211,238,.10),transparent 58%);box-shadow:inset 0 0 18px rgba(35,211,238,.06);pointer-events:none}}.alerts-refresh:hover{{transform:translateY(-1px);border-color:rgba(35,211,238,.95);background:linear-gradient(145deg,rgba(16,31,46,.88),rgba(7,15,25,.94));box-shadow:0 18px 42px rgba(0,0,0,.32),0 0 18px rgba(35,211,238,.42),0 0 44px rgba(35,211,238,.24),inset 0 1px 0 rgba(255,255,255,.065),inset 0 0 24px rgba(35,211,238,.08)}}.alerts-refresh:active{{transform:translateY(1px) scale(.99)}}.alerts-refresh[aria-busy="true"],.alerts-refresh.refreshing{{cursor:wait;filter:saturate(1.18);border-color:rgba(35,211,238,1);box-shadow:0 18px 46px rgba(0,0,0,.34),0 0 22px rgba(35,211,238,.52),0 0 56px rgba(35,211,238,.30),inset 0 0 28px rgba(35,211,238,.10)}}.alerts-refresh-icon{{position:relative;z-index:1;display:block;font-size:25px;line-height:1;color:var(--refresh-accent);text-shadow:0 0 10px rgba(35,211,238,.35),0 0 24px rgba(35,211,238,.20);transform-origin:center}}.alerts-refresh:hover .alerts-refresh-icon{{text-shadow:0 0 12px rgba(35,211,238,.62),0 0 30px rgba(35,211,238,.34)}}.alerts-refresh[aria-busy="true"] .alerts-refresh-icon,.alerts-refresh.refreshing .alerts-refresh-icon{{animation:refresh-spin .72s linear infinite}}@keyframes refresh-spin{{to{{transform:rotate(360deg)}}}}.subtitle{{margin-top:6px;color:#8d9cad;font-size:13px}}.search-wrap{{position:relative}}.search-wrap:before{{content:'⌕';position:absolute;left:14px;top:50%;transform:translateY(-50%);color:#8292a5}}.search{{width:100%;border:1px solid rgba(148,163,184,.12);border-radius:10px;padding:11px 42px 11px 36px;color:#dce9f8;background:#0b131c;font:inherit;outline:none}}.kbd{{position:absolute;right:10px;top:50%;transform:translateY(-50%);color:#97a6b9;border:1px solid rgba(148,163,184,.16);border-radius:6px;padding:2px 6px;font-size:11px}}.toggle-stack{{display:grid;gap:8px;align-content:center}}.time-filter{{display:grid;gap:6px;width:154px;min-width:0;color:#9fb0c4;font-size:11px;font-weight:800;letter-spacing:.01em}}.last-seen-filter{{width:138px}}.sort-default-filter{{width:178px}}.time-filter select{{width:100%;height:44px;border:1px solid rgba(34,211,238,.30);border-radius:12px;padding:0 34px 0 12px;color:#dce9f8;background:#0b131c;font:inherit;font-size:12px;font-weight:800;outline:none;box-shadow:inset 0 0 18px rgba(34,211,238,.035)}}.time-filter select:focus{{border-color:rgba(34,211,238,.72);box-shadow:0 0 0 3px rgba(34,211,238,.10),inset 0 0 18px rgba(34,211,238,.05)}}.toggle-wrap{{display:inline-flex;align-items:center;gap:9px;color:#d8e6f8;font-size:13px;font-weight:750;white-space:nowrap}}.toggle-wrap input{{position:absolute;opacity:0}}.toggle-slider{{position:relative;width:38px;height:20px;border-radius:999px;background:rgba(34,211,238,.20);border:1px solid rgba(34,211,238,.36)}}.toggle-slider:before{{content:'';position:absolute;width:16px;height:16px;left:18px;top:1px;border-radius:999px;background:#8ff4ff;box-shadow:0 0 12px rgba(34,211,238,.42);transition:transform .16s ease}}.toggle-wrap input:not(:checked)+.toggle-slider{{background:rgba(15,23,42,.88);border-color:rgba(148,163,184,.24)}}.toggle-wrap input:not(:checked)+.toggle-slider:before{{transform:translateX(-17px);background:#94a3b8;box-shadow:none}}.avatar{{display:flex;align-items:center;align-self:end;justify-content:flex-end;gap:8px;height:44px;min-width:0;padding-bottom:1px}}@media(max-width:1320px){{.avatar>span{{display:none}}}}.avatar-bubble{{width:44px;height:44px;display:grid;place-items:center;border-radius:999px;background:#0b131c;border:1px solid rgba(148,163,184,.14);font-size:12px;font-weight:900}}
.api-pagination{{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:13px 14px;flex-wrap:wrap;border-top:1px solid rgba(148,163,184,.10);background:rgba(7,16,24,.36)}}.api-page-size,.api-page-controls{{display:inline-flex;align-items:center;gap:9px}}.api-page-size span{{color:#91a4ba;font-size:12px;font-weight:850}}.api-page-size select,.api-page-controls select{{height:34px;border:1px solid rgba(34,211,238,.24);border-radius:9px;padding:0 28px 0 10px;color:#dce9f8;background:#0b131c;font:12px/1 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-weight:850;outline:none}}.api-page-size select:focus,.api-page-controls select:focus{{border-color:rgba(34,211,238,.68);box-shadow:0 0 0 3px rgba(34,211,238,.10)}}.api-page-button{{padding:8px 10px}}.api-page-button:disabled{{opacity:.42;cursor:not-allowed}}.api-page-status{{color:#91a4ba;font-size:12px;margin-left:auto}}.api-detail-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin:0 0 14px}}.api-detail-grid div{{border:1px solid rgba(148,163,184,.12);border-radius:8px;padding:8px;background:rgba(148,163,184,.04)}}.api-detail-grid b{{display:block;color:#8ff4ff;font-size:10px;text-transform:uppercase;letter-spacing:.08em}}.api-detail-grid span{{display:block;color:#dce9f8;font-size:12px;margin-top:4px}}.api-detail-loading{{margin:0 0 12px;color:#8ff4ff;font-size:12px}}.api-detail-error{{margin:0 0 12px;color:#fb7185;font-size:12px}}.view-section{{display:none}}.view-section.active{{display:block}}.app-shell[data-view="overview"] .alerts-only{{display:none}}.app-shell[data-view="overview"] .topbar{{grid-template-columns:minmax(240px,1fr) auto}}.app-shell[data-view="overview"] .avatar{{justify-self:end}}.overview-grid{{display:grid;gap:16px}}.flow-hero{{display:grid;grid-template-columns:minmax(260px,.52fr) minmax(520px,1fr);gap:20px;align-items:stretch;border:1px solid rgba(148,163,184,.14);border-radius:14px;padding:20px;background:linear-gradient(135deg,#0d1620 0%,#101923 58%,#0b131c 100%);box-shadow:0 22px 48px rgba(0,0,0,.24),inset 0 1px 0 rgba(255,255,255,.035)}}.flow-copy{{display:flex;flex-direction:column;justify-content:center;min-width:0;padding:8px 2px}}.flow-kicker{{width:max-content;border:1px solid rgba(34,211,238,.28);border-radius:999px;padding:6px 10px;color:#8ff4ff;background:rgba(34,211,238,.06);font-size:11px;font-weight:950;text-transform:uppercase;letter-spacing:.12em}}.flow-copy h2{{margin:16px 0 10px;color:#f5f9ff;font-size:36px;line-height:1;letter-spacing:-.04em}}.flow-copy p{{max-width:46ch;margin:0;color:#aab8ca;font-size:14px;line-height:1.6}}.network-diagram{{position:relative;display:grid;grid-template-columns:1fr 86px 1fr 86px 1fr;grid-template-rows:minmax(146px,auto) 72px minmax(86px,auto);gap:10px;align-items:center;min-height:340px;padding:18px;border:1px solid rgba(34,211,238,.13);border-radius:12px;background:linear-gradient(180deg,rgba(7,16,24,.58),rgba(6,12,20,.82))}}.flow-node{{position:relative;z-index:2;display:grid;justify-items:start;gap:6px;min-width:0;min-height:132px;border:1px solid rgba(148,163,184,.18);border-radius:12px;padding:15px;background:#0b131c;box-shadow:0 12px 30px rgba(0,0,0,.22),inset 0 0 28px rgba(34,211,238,.035)}}.flow-node strong{{color:#f4f8ff;font-size:15px;line-height:1.2}}.flow-node span:not(.node-icon){{color:#91a4ba;font-size:12px}}.flow-node em{{align-self:end;color:#8ff4ff;font-size:11px;font-style:normal;font-weight:850;text-transform:uppercase;letter-spacing:.06em}}.node-icon{{width:42px;height:42px;display:grid;place-items:center;border-radius:11px;color:#061018;background:#8ff4ff;font-size:13px;font-weight:950;box-shadow:0 0 18px rgba(34,211,238,.24)}}.node-so{{grid-column:1;grid-row:1;border-color:rgba(251,113,133,.34)}}.node-so .node-icon{{background:linear-gradient(135deg,#fb7185,#f6c76d)}}.node-pi{{grid-column:3;grid-row:1;border-color:rgba(246,199,109,.34)}}.node-pi .node-icon{{background:linear-gradient(135deg,#f6c76d,#86efac)}}.node-mac{{grid-column:5;grid-row:1;border-color:rgba(34,197,94,.34)}}.node-mac .node-icon{{background:linear-gradient(135deg,#8ff4ff,#22c55e)}}.flow-link{{position:relative;z-index:1;height:2px;background:linear-gradient(90deg,rgba(34,211,238,.22),rgba(143,244,255,.92),rgba(34,211,238,.22))}}.flow-link:after{{content:"";position:absolute;right:-2px;top:50%;width:9px;height:9px;border-top:2px solid #8ff4ff;border-right:2px solid #8ff4ff;transform:translateY(-50%) rotate(45deg)}}.flow-link span{{position:absolute;left:50%;top:-26px;transform:translateX(-50%);white-space:nowrap;border:1px solid rgba(148,163,184,.16);border-radius:999px;padding:4px 8px;color:#c7d4e4;background:#071018;font-size:10px;font-weight:850}}.link-one{{grid-column:2;grid-row:1}}.link-two{{grid-column:4;grid-row:1}}.flow-fanout{{grid-column:5;grid-row:2;justify-self:center;width:2px;height:64px;background:linear-gradient(180deg,rgba(143,244,255,.85),rgba(34,211,238,.08));position:relative}}.flow-fanout:after{{content:"";position:absolute;left:-180px;right:-180px;bottom:0;height:2px;background:linear-gradient(90deg,rgba(34,211,238,.06),rgba(143,244,255,.72),rgba(34,211,238,.06))}}.flow-output{{z-index:2;display:grid;gap:5px;min-height:72px;border:1px solid rgba(148,163,184,.16);border-radius:10px;padding:12px;background:#09111a}}.flow-output b{{color:#f2f7ff;font-size:13px}}.flow-output span{{color:#9aaabd;font-size:11px;line-height:1.35}}.output-dashboard{{grid-column:2;grid-row:3;border-color:rgba(34,211,238,.30)}}.output-markdown{{grid-column:3;grid-row:3;border-color:rgba(246,199,109,.30)}}.output-ai{{grid-column:4;grid-row:3;border-color:rgba(34,197,94,.30)}}.output-phone{{grid-column:5;grid-row:3;border-color:rgba(251,113,133,.30)}}.overview-status{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}}.status-tile{{border:1px solid rgba(148,163,184,.13);border-radius:10px;padding:15px 16px;background:#0d1620}}.status-tile span{{display:block;color:#8ff4ff;font-size:11px;font-weight:950;text-transform:uppercase;letter-spacing:.08em}}.status-tile strong{{display:block;margin-top:8px;color:#f3f8ff;font-size:16px}}.status-tile em{{display:block;margin-top:5px;color:#9aa8b8;font-size:12px;font-style:normal;line-height:1.35}}.metrics{{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:14px;margin-bottom:14px}}.metrics.verbose-metrics{{grid-template-columns:repeat(2,minmax(0,1fr))}}.metric-card{{display:flex;align-items:center;gap:13px;min-width:0;overflow:hidden;border:1px solid rgba(148,163,184,.12);border-radius:10px;padding:15px 16px;background:#0d1620;min-height:88px;transition:border-color .16s ease,box-shadow .16s ease}}.metrics.verbose-metrics .metric-card{{border-color:rgba(34,211,238,.18);box-shadow:inset 0 0 24px rgba(34,211,238,.035)}}.metric-icon{{width:56px;height:56px;display:grid;place-items:center;flex:0 0 56px;border-radius:16px;border:1px solid rgba(34,211,238,.20);background:radial-gradient(circle at 50% 45%,rgba(34,211,238,.15),rgba(34,211,238,.055) 48%,rgba(15,23,42,.18));box-shadow:inset 0 0 20px rgba(34,211,238,.065),0 0 18px rgba(34,211,238,.095)}}.metric-icon img{{width:50px;height:50px;object-fit:contain;object-position:center;display:block;filter:drop-shadow(0 0 9px rgba(34,211,238,.42))}}.ai-activity-card{{position:relative;align-items:stretch!important}}.ai-activity-main{{display:grid!important;grid-template-rows:auto auto 1fr;align-content:start!important;width:100%!important;min-width:0!important}}.ai-activity-icon{{position:relative;color:#8ff4ff;font-size:17px;font-weight:950;letter-spacing:0}}.ai-activity-icon img{{width:52px;height:52px;border-radius:14px;filter:drop-shadow(0 0 10px rgba(34,211,238,.36))}}.ai-activity-active{{border-color:rgba(34,211,238,.42);box-shadow:0 0 0 1px rgba(34,211,238,.10),0 0 28px rgba(34,211,238,.16),inset 0 0 24px rgba(34,211,238,.045)}}.ai-activity-active .ai-activity-icon{{animation:ai-core-pulse 1.1s ease-in-out infinite}}.ai-activity-active .ai-activity-icon:after{{content:"";position:absolute;inset:-7px;border:1px solid rgba(34,211,238,.58);border-radius:20px;animation:ai-ring 1.35s ease-out infinite}}@keyframes ai-core-pulse{{0%,100%{{transform:scale(1);box-shadow:inset 0 0 20px rgba(34,211,238,.065),0 0 18px rgba(34,211,238,.095)}}50%{{transform:scale(1.04);box-shadow:inset 0 0 24px rgba(34,211,238,.12),0 0 26px rgba(34,211,238,.34)}}}}@keyframes ai-ring{{0%{{opacity:.75;transform:scale(.78)}}80%,100%{{opacity:0;transform:scale(1.22)}}}}.metric-main{{min-width:76px}}.metric-card strong{{display:block;color:#f3f8ff;font-size:16px}}.metric-card .metric-ratio{{font-size:18px;line-height:1.05;letter-spacing:0}}.metric-card .metric-ratio span{{display:inline;color:inherit;font:inherit;margin:0}}.metric-card span{{display:block;color:#9aa8b8;font-size:12px;margin-top:2px}}.metric-extra{{display:none;margin-left:auto;padding-left:10px;min-width:116px;border-left:1px solid rgba(148,163,184,.12)}}.metrics.verbose-metrics .metric-extra{{display:grid}}.severity-breakdown{{grid-template-columns:repeat(2,max-content);gap:4px 7px;align-items:center}}.sev-chip{{display:inline-flex!important;align-items:center;gap:4px;margin:0!important;font-size:10.5px;color:#9fb0c4;white-space:nowrap}}.sev-chip b{{font-size:11px;color:#eef8ff}}.sev-critical b{{color:var(--red)}}.sev-high b{{color:var(--orange)}}.sev-medium b{{color:var(--amber)}}.sev-low b{{color:#86efac}}.sev-informational b{{color:#93c5fd}}.metric-detail{{gap:5px}}.metric-detail-row{{display:flex!important;justify-content:space-between;gap:10px;margin:0!important;color:#9fb0c4;font-size:11px;white-space:nowrap}}.metric-detail-row b{{color:#8ff4ff;font-size:11px}}.metric-detail-row span{{margin:0!important;max-width:145px;overflow:hidden;text-overflow:ellipsis}}.workspace{{display:block}}.table-card{{overflow:auto;border:1px solid rgba(148,163,184,.12);border-radius:10px;background:#0d1620}}.alert-table{{width:100%;min-width:1440px;border-collapse:collapse}}th,td{{text-align:left;border-bottom:1px solid rgba(148,163,184,.10);vertical-align:middle}}th{{padding:10px 9px;color:#96a6b8;font-size:11px;font-weight:850;background:#101b26}}.sort-header{{display:inline-flex;align-items:center;gap:5px;width:100%;min-width:0;border:0;padding:0;color:inherit;background:transparent;font:inherit;font-weight:850;text-align:inherit;cursor:pointer}}.sort-header:hover{{color:#8ff4ff}}.sort-indicator{{display:inline-grid;place-items:center;min-width:10px;color:#8ff4ff;font-size:10px;line-height:1;opacity:.45}}.sort-header[data-sort-active="true"]{{color:#8ff4ff}}.sort-header[data-sort-active="true"] .sort-indicator{{opacity:1}}td{{padding:8px 9px;color:#d7e3f1;font-size:13px}}.report-row{{cursor:pointer;transition:background .14s ease,box-shadow .14s ease}}.report-row:hover{{background:rgba(34,211,238,.035)}}.report-row.selected{{background:rgba(34,211,238,.08);box-shadow:inset 3px 0 0 var(--cyan)}}.select-cell{{width:42px}}.row-check{{display:grid;place-items:center;width:18px;height:18px;border:1px solid rgba(148,163,184,.26);border-radius:5px;color:transparent}}.report-row.selected .row-check{{color:white;background:linear-gradient(135deg,#23d3ee,#1fb6ce);border-color:transparent}}.severity-header,.severity-cell{{text-align:center}}.count-cell{{text-align:center}}.ip-header{{text-align:center}}.ip-cell{{text-align:right;width:126px;padding-right:3px}}.port-header,.port-cell{{text-align:left;width:76px}}.port-cell{{padding-left:4px}}.last-seen-cell{{white-space:nowrap;font-variant-numeric:tabular-nums;color:#b8c6d8;font-size:12px}}.severity-label{{font-size:11px;font-weight:900;text-transform:uppercase}}.severity-text-critical{{color:var(--red)}}.severity-text-high{{color:var(--orange)}}.severity-text-medium{{color:var(--amber)}}.severity-text-low{{color:#86efac}}.severity-text-informational{{color:#93c5fd}}.ai-status-cell,.enrichment-status-cell,.pcap-status-cell{{text-align:center;white-space:nowrap}}.ai-status-pill,.enrichment-status-pill,.pcap-status-pill{{display:inline-block;padding:0;border:0;background:transparent;font-size:11px;font-weight:900;line-height:1;text-transform:uppercase;letter-spacing:0;color:#9fb0c4;white-space:nowrap}}.ai-status-analyzed{{color:var(--cyan);text-shadow:0 0 10px rgba(34,211,238,.18)}}.ai-status-analyzing{{color:var(--green);text-shadow:0 0 10px rgba(34,197,94,.22)}}.ai-status-queued{{color:var(--amber)}}.ai-status-not-queued{{color:#94a3b8}}.enrichment-status-enriched,.pcap-status-analyzed{{color:var(--green);text-shadow:0 0 10px rgba(34,197,94,.18)}}.enrichment-status-checked{{color:var(--cyan)}}.enrichment-status-pending,.pcap-status-queued{{color:var(--amber)}}.enrichment-status-error,.pcap-status-error{{color:var(--red)}}.enrichment-status-none,.pcap-status-none{{color:#94a3b8}}th:nth-child(5),td.alert-cell{{width:30%;min-width:300px}}.workspace.panel-hidden th:nth-child(5),.workspace.panel-hidden td.alert-cell{{width:34%;min-width:380px}}.alert-cell strong{{display:block;color:#f2f7ff;line-height:1.35;font-size:13px}}.summary-cell{{color:#aeb9c7;line-height:1.35;max-width:360px}}.endpoint-cell code{{color:#dce9f8;background:rgba(148,163,184,.05);border:1px solid rgba(148,163,184,.12);border-radius:6px;padding:4px 7px;font-size:12px;white-space:nowrap}}.wide-only{{display:none}}.workspace.panel-hidden .wide-only{{display:table-cell}}.workspace.panel-hidden .summary-cell{{max-width:620px}}.source-cell{{width:142px;min-width:142px}}.source-cell code{{color:#aeeeff;background:rgba(34,211,238,.06);border:1px solid rgba(34,211,238,.12);border-radius:6px;padding:3px 6px;font-size:11px;white-space:nowrap;overflow-wrap:normal}}.action-cell{{white-space:nowrap}}.ack-button{{border:1px solid rgba(148,163,184,.16);border-radius:7px;padding:8px 11px;color:#dce9f8;background:#0b131c;font-size:12px;font-weight:850;cursor:pointer}}.ack-button+.ack-button{{margin-left:6px}}.ack-button:hover{{border-color:rgba(34,211,238,.40);color:#8ff4ff}}.suppress-button:hover{{border-color:rgba(251,113,133,.45);color:#fb7185}}.suppression-note{{margin:0 0 14px;border:1px solid rgba(251,113,133,.24);border-radius:10px;padding:12px 14px;background:rgba(251,113,133,.07)}}.suppression-note h3{{margin:0 0 7px;color:#fb7185;font-size:12px;text-transform:uppercase;letter-spacing:.08em}}.suppression-note p{{margin:0;color:#f2d3d9;font-size:13px;line-height:1.45}}.suppression-note small{{display:block;margin-top:7px;color:#9aa8b8;font-size:11px}}.modal-backdrop,.suppress-modal{{position:fixed;inset:0;z-index:10000;display:flex;align-items:center;justify-content:center;width:100vw;height:100dvh;min-height:100vh;padding:24px;background:rgba(2,6,12,.72);backdrop-filter:blur(10px)}}.modal-backdrop[hidden],.suppress-modal[hidden]{{display:none!important}}.modal-card,.suppress-dialog{{width:min(520px,calc(100vw - 48px));max-height:calc(100dvh - 48px);overflow:auto;border:1px solid rgba(251,113,133,.26);border-radius:14px;padding:18px;background:#0d1620;box-shadow:0 28px 80px rgba(0,0,0,.52),inset 0 1px 0 rgba(255,255,255,.04)}}.modal-card h2,.suppress-dialog h2{{margin:0 0 8px;color:#f5f9ff;font-size:20px}}.modal-card p,.suppress-dialog p{{margin:0 0 14px;color:#aeb9c7;font-size:13px;line-height:1.5}}.modal-card textarea,.suppress-dialog textarea{{width:100%;min-height:92px;resize:vertical;border:1px solid rgba(148,163,184,.18);border-radius:10px;padding:11px 12px;color:#dce9f8;background:#071018;font:13px/1.45 inherit;outline:none}}.modal-card textarea:focus,.suppress-dialog textarea:focus{{border-color:rgba(251,113,133,.55);box-shadow:0 0 0 3px rgba(251,113,133,.10)}}.modal-meta,.suppress-dialog-footer{{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:12px;color:#91a4ba;font-size:12px}}.modal-actions,.suppress-actions{{display:flex;justify-content:flex-end;gap:9px;margin-top:14px}}.modal-button{{border:1px solid rgba(148,163,184,.18);border-radius:9px;padding:9px 12px;color:#dce9f8;background:#0b131c;font-weight:850;cursor:pointer}}.modal-button:hover{{border-color:rgba(34,211,238,.40);color:#8ff4ff}}.confirm-suppress,.modal-button.primary{{border-color:rgba(251,113,133,.45);color:#ffd6de}}.confirm-suppress:hover,.modal-button.primary:hover{{border-color:rgba(251,113,133,.75);color:#fff;background:rgba(251,113,133,.12)}}.confirm-suppress:disabled,.modal-button.primary:disabled{{opacity:.45;cursor:not-allowed}}.report-row-group[data-acknowledged='true'] .report-row,.report-row-group[data-suppressed='true'] .report-row{{opacity:.56}}.menu-cell{{color:#8ea0b3;text-align:center;font-size:20px}}.detail-template-row{{display:none}}.detail-template-row>td{{overflow:visible;padding:12px 18px 18px}}.report-row-group.expanded .detail-template-row{{display:table-row}}.report-row-group.expanded .report-row{{background:rgba(34,211,238,.08);box-shadow:inset 3px 0 0 var(--cyan)}}.pinned-alert-viewport{{position:fixed;left:0;top:var(--sticky-row-top);z-index:80;display:none;overflow:hidden;border:1px solid rgba(34,211,238,.20);border-radius:0 0 10px 10px;background:#101b26;box-shadow:0 14px 28px rgba(0,0,0,.36),inset 3px 0 0 var(--cyan)}}.pinned-alert-viewport.visible{{display:block}}.pinned-alert-row{{display:grid;grid-template-columns:42px 62px 74px 166px minmax(300px,1.25fr) minmax(126px,.68fr) minmax(126px,.68fr) 82px 112px 112px 142px 62px 62px 118px 38px;align-items:stretch;background:#101b26;will-change:transform}}.pinned-alert-cell{{display:flex;align-items:center;padding:10px 12px;border-bottom:1px solid rgba(148,163,184,.10);color:#d7e3f1;font-size:13px;background:#101b26}}.pinned-alert-cell.severity-cell{{justify-content:center;text-align:center}}.pinned-alert-cell.count-cell{{justify-content:center;text-align:center}}.pinned-alert-cell.ip-cell{{justify-content:flex-end;text-align:right;padding-right:4px}}.pinned-alert-cell.port-cell{{justify-content:flex-start;text-align:left;padding-left:4px;margin-left:-14px}}.pinned-alert-cell code{{color:#dce9f8;background:rgba(148,163,184,.05);border:1px solid rgba(148,163,184,.12);border-radius:6px;padding:4px 7px;font-size:12px;white-space:nowrap}}.detail-template{{scroll-margin-top:calc(var(--sticky-row-top) + 46px);width:var(--detail-visible-width,100%);max-width:var(--detail-visible-width,100%);min-width:0;margin-right:24px;padding:18px;border:1px solid rgba(34,211,238,.14);border-radius:12px;background:#09111a;box-shadow:inset 3px 0 0 rgba(34,211,238,.55);overflow:hidden;transform:translateX(var(--detail-visible-x,0px));transform-origin:left top}}.detail-label{{margin-bottom:12px;color:#8ff4ff;font-size:12px;font-weight:900;letter-spacing:.08em;text-transform:uppercase}}
.detail-report-section{{margin:16px 0 18px;border:1px solid rgba(148,163,184,.12);border-radius:12px;background:linear-gradient(180deg,rgba(13,22,32,.72),rgba(7,16,24,.48));box-shadow:inset 3px 0 0 rgba(34,211,238,.18),inset 0 1px 0 rgba(255,255,255,.025);overflow:hidden}}
.detail-report-section>h2,.detail-report-section>h3{{margin:0!important;padding:13px 16px!important;border-bottom:1px solid rgba(148,163,184,.11);background:rgba(16,27,38,.76);color:#f4f8ff!important;font-size:17px!important;line-height:1.2!important;letter-spacing:-.01em!important}}
.detail-report-section>h2:before,.detail-report-section>h3:before{{content:'';display:inline-block;width:7px;height:7px;margin-right:9px;border-radius:999px;background:#8ff4ff;box-shadow:0 0 12px rgba(34,211,238,.34);vertical-align:middle}}
.detail-report-section>p,.detail-report-section>ul,.detail-report-section>ol,.detail-report-section>blockquote,.detail-report-section>pre,.detail-report-section>.table-wrap,.detail-report-section>details,.detail-report-section>h4,.detail-report-section>h5,.detail-report-section>h6{{margin-left:16px!important;margin-right:16px!important}}
.detail-report-section>p:first-of-type{{margin-top:14px!important}}
.detail-report-section>p:last-child,.detail-report-section>ul:last-child,.detail-report-section>ol:last-child,.detail-report-section>.table-wrap:last-child{{margin-bottom:16px!important}}
.markdown-body .table-wrap{{max-width:100%;overflow:auto;border:1px solid rgba(148,163,184,.13);border-radius:10px;background:rgba(7,16,24,.42)}}
.markdown-body .table-wrap table{{width:100%;border-collapse:collapse;table-layout:auto}}
.markdown-body .table-wrap th{{position:sticky;top:0;z-index:1;padding:11px 12px;color:#9fb0c4;background:#101b26;font-size:11px;font-weight:900;line-height:1.2;text-transform:none;letter-spacing:0}}
.markdown-body .table-wrap td{{padding:11px 12px;color:#d7e3f1;font-size:12.5px;line-height:1.45;vertical-align:top;overflow-wrap:anywhere}}
.markdown-body .table-wrap tbody tr:nth-child(even){{background:rgba(148,163,184,.025)}}
.markdown-body .table-wrap tbody tr:hover{{background:rgba(34,211,238,.035)}}
.markdown-body .public-enrichment-table table{{min-width:980px;table-layout:fixed}}
.markdown-body .public-enrichment-table th:nth-child(1),.markdown-body .public-enrichment-table td:nth-child(1){{width:128px;overflow-wrap:normal;word-break:normal}}
.markdown-body .public-enrichment-table th:nth-child(2),.markdown-body .public-enrichment-table td:nth-child(2){{width:150px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;font-size:12px;overflow-wrap:anywhere}}
.markdown-body .public-enrichment-table th:nth-child(3),.markdown-body .public-enrichment-table td:nth-child(3){{width:58px;text-align:center;overflow-wrap:normal}}
.markdown-body .public-enrichment-table th:nth-child(4),.markdown-body .public-enrichment-table td:nth-child(4){{width:100px;overflow-wrap:normal}}
.markdown-body .public-enrichment-table th:nth-child(5),.markdown-body .public-enrichment-table td:nth-child(5){{width:84px;text-align:center;overflow-wrap:normal}}
.markdown-body .public-enrichment-table th:nth-child(6),.markdown-body .public-enrichment-table td:nth-child(6){{width:auto;min-width:250px}}
.markdown-body .public-enrichment-table th:nth-child(7),.markdown-body .public-enrichment-table td:nth-child(7){{width:190px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;font-size:11.5px;white-space:normal;overflow-wrap:normal}}
.markdown-body .public-enrichment-skipped-table table{{min-width:860px}}
.markdown-body .public-enrichment-skipped-table th:nth-child(1),.markdown-body .public-enrichment-skipped-table td:nth-child(1){{width:132px;overflow-wrap:normal}}
.markdown-body .public-enrichment-skipped-table th:nth-child(2),.markdown-body .public-enrichment-skipped-table td:nth-child(2){{width:180px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;font-size:12px}}
.selected-panel{{position:sticky;top:92px;border:1px solid rgba(148,163,184,.12);border-radius:10px;background:#101923;min-height:640px;overflow:hidden}}.panel-top{{display:flex;justify-content:space-between;padding:16px;border-bottom:1px solid rgba(148,163,184,.10)}}.close-button{{border:0;color:#9baabd;background:transparent;font-size:22px;cursor:pointer}}.panel-content{{padding:16px}}.panel-severity-row{{display:flex;justify-content:space-between;gap:12px;margin-bottom:10px}}.panel-title{{margin:0 0 10px;color:#fff;font-size:20px;line-height:1.22}}.risk-score{{width:62px;height:62px;display:grid;place-items:center;border-radius:999px;color:#ffdd74;border:3px solid rgba(246,199,109,.78);background:rgba(246,199,109,.07);font-weight:950}}.risk-score small{{display:block;color:#aeb9c7;font-size:9px;text-align:center}}.panel-meta{{display:flex;gap:14px;color:#9baabd;font-size:12px;padding-bottom:14px;border-bottom:1px solid rgba(148,163,184,.10);flex-wrap:wrap}}.panel-section{{padding:14px 0;border-bottom:1px solid rgba(148,163,184,.10)}}.panel-section h3{{margin:0 0 9px;color:#f2f7ff;font-size:13px}}.panel-section p{{margin:0;color:#aeb9c7;line-height:1.55;font-size:13px}}.enrichment-row,.next-step{{display:flex;justify-content:space-between;color:#b9c6d6;font-size:12px;padding:5px 0}}.enrichment-row:before,.next-step:before{{content:'✓';color:#4ade80;margin-right:5px}}.verdict{{display:flex;gap:10px;border:1px solid rgba(246,199,109,.22);border-radius:8px;padding:12px;background:rgba(246,199,109,.10);color:#f5d482}}.open-investigation{{width:100%;margin-top:12px;border:0;border-radius:7px;padding:10px 12px;color:#061018;background:linear-gradient(135deg,#22d3ee,#19a9c3);font-weight:900;cursor:pointer}}.markdown-panel{{display:none;margin-top:12px;max-height:420px;overflow:auto;border:1px solid rgba(148,163,184,.12);border-radius:8px;padding:12px;background:#09111a}}.markdown-panel.open{{display:block}}.markdown-body{{max-width:100%;min-width:0;color:#dbe7f6;line-height:1.6;font-size:13px;overflow-wrap:anywhere;word-break:break-word}}.detail-template .markdown-body,.detail-template .api-detail-content{{max-width:100%;min-width:0;overflow-wrap:anywhere;word-break:break-word}}.detail-template .markdown-body p,.detail-template .markdown-body li,.detail-template .markdown-body dd,.detail-template .markdown-body td,.detail-template .markdown-body th{{max-width:100%;overflow-wrap:anywhere;word-break:break-word}}.detail-template .markdown-body code,.detail-template .api-detail-content code{{white-space:normal;overflow-wrap:anywhere;word-break:break-word}}.detail-template .markdown-body pre,.detail-template .api-detail-content pre{{max-width:100%;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;overflow-x:hidden}}.detail-template .markdown-body pre code,.detail-template .api-detail-content pre code{{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word}}.detail-template .markdown-body table{{display:block;max-width:100%;overflow-x:auto;border-collapse:collapse}}.detail-template .markdown-body .public-enrichment-table table{{display:table!important;width:100%!important;min-width:980px!important;table-layout:fixed!important;border-collapse:collapse!important;overflow:visible!important}}.detail-template .markdown-body .public-enrichment-table th:nth-child(1),.detail-template .markdown-body .public-enrichment-table td:nth-child(1){{width:128px!important}}.detail-template .markdown-body .public-enrichment-table th:nth-child(2),.detail-template .markdown-body .public-enrichment-table td:nth-child(2){{width:150px!important}}.detail-template .markdown-body .public-enrichment-table th:nth-child(3),.detail-template .markdown-body .public-enrichment-table td:nth-child(3){{width:58px!important}}.detail-template .markdown-body .public-enrichment-table th:nth-child(4),.detail-template .markdown-body .public-enrichment-table td:nth-child(4){{width:100px!important}}.detail-template .markdown-body .public-enrichment-table th:nth-child(5),.detail-template .markdown-body .public-enrichment-table td:nth-child(5){{width:84px!important}}.detail-template .markdown-body .public-enrichment-table th:nth-child(7),.detail-template .markdown-body .public-enrichment-table td:nth-child(7){{width:190px!important}}.detail-template .markdown-body img,.detail-template .markdown-body svg{{max-width:100%;height:auto}}.alert-timeline-section{{margin:12px 0 16px;border:1px solid rgba(34,211,238,.16);border-radius:10px;background:#071018;overflow:hidden;box-shadow:inset 0 0 0 1px rgba(255,255,255,.015)}}.alert-timeline-section summary{{display:flex;align-items:center;gap:12px;cursor:pointer;list-style:none;padding:11px 14px;color:#f5f9ff;background:#0b151f;font-size:13px;font-weight:900;border-bottom:1px solid rgba(148,163,184,.10)}}.alert-timeline-section summary::-webkit-details-marker{{display:none}}.alert-timeline-section summary:before{{content:"▾";display:inline-grid;place-items:center;width:18px;height:18px;border:1px solid rgba(34,211,238,.22);border-radius:6px;color:#8ff4ff;background:rgba(34,211,238,.05);font-size:11px;transition:transform .16s ease}}.alert-timeline-section:not([open]) summary{{border-bottom:0}}.alert-timeline-section:not([open]) summary:before{{transform:rotate(-90deg)}}.alert-timeline-section summary span{{margin-left:0;color:#91a4ba;font-size:11px;font-weight:800}}.alert-timeline-body{{max-height:430px;overflow:auto;padding:18px 16px 16px;background:#071018}}.alert-timeline-summary{{display:grid;gap:8px;margin:0 0 0;color:#aeb9c7;font-size:13px;line-height:1.35}}.alert-timeline-summary div{{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:12px;align-items:baseline}}.alert-timeline-summary dt{{color:#aeb9c7;font-weight:900}}.alert-timeline-summary dd{{margin:0;color:#dce9f8;overflow-wrap:anywhere}}.alert-timeline-rail{{position:relative;height:34px;margin:48px 24px 40px;border-radius:999px;background:linear-gradient(90deg,rgba(34,211,238,.14),rgba(143,244,255,.24),rgba(34,211,238,.14));box-shadow:inset 0 0 0 1px rgba(34,211,238,.12)}}.alert-timeline-rail:before{{content:"";position:absolute;left:0;right:0;top:50%;height:2px;border-radius:999px;background:rgba(143,244,255,.42);transform:translateY(-50%)}}.alert-timeline-marker{{position:absolute;top:50%;z-index:1;width:var(--marker-size,8px);height:var(--marker-size,8px);border-radius:999px;background:#8ff4ff;border:2px solid #071018;box-shadow:0 0 0 1px rgba(34,211,238,.24),0 0 calc(var(--marker-size,8px) * .9) rgba(34,211,238,.32);transform:translate(-50%,-50%);transition:transform .14s ease,box-shadow .14s ease}}.alert-timeline-marker:hover{{z-index:3;transform:translate(-50%,-50%) scale(1.18);box-shadow:0 0 0 3px rgba(34,211,238,.18),0 0 calc(var(--marker-size,8px) * 1.25) rgba(34,211,238,.52)}}.alert-timeline-marker span{{position:absolute;left:50%;top:-42px;transform:translateX(-50%);padding:2px 7px;border:1px solid rgba(148,163,184,.20);border-radius:999px;color:#dce9f8;background:#071018;font-size:10px;font-weight:900;white-space:nowrap}}.alert-timeline-marker.marker-first{{background:#86efac;box-shadow:0 0 0 2px rgba(34,197,94,.18),0 0 calc(var(--marker-size,12px) * 1.05) rgba(34,197,94,.38)}}.alert-timeline-marker.marker-last{{background:#f6c76d;box-shadow:0 0 0 2px rgba(246,199,109,.18),0 0 calc(var(--marker-size,12px) * 1.05) rgba(246,199,109,.38)}}.alert-timeline-table{{margin-top:18px;max-height:220px;background:#09111a;border-color:rgba(148,163,184,.12)}}.alert-timeline-table table{{min-width:1060px}}.alert-timeline-table th{{top:0;padding:9px 12px;font-size:10px;background:#101923;color:#91a4ba}}.alert-timeline-table td{{padding:9px 12px;font-size:12px}}.alert-timeline-table tbody tr:hover{{background:rgba(34,211,238,.035)}}.alert-timeline-table code{{white-space:nowrap;color:#dce9f8;background:rgba(148,163,184,.06);border:1px solid rgba(148,163,184,.10);border-radius:6px;padding:3px 6px}}.raw-alert-details{{margin:14px 0;border:1px solid rgba(148,163,184,.18);border-radius:10px;background:#071018;overflow:hidden}}.raw-alert-details summary{{cursor:pointer;list-style:none;padding:12px 14px;color:#8ff4ff;font-weight:900;letter-spacing:.04em;text-transform:uppercase;border-bottom:1px solid transparent;background:rgba(34,211,238,.06)}}.raw-alert-details summary::-webkit-details-marker{{display:none}}.raw-alert-details summary:before{{content:'▸';display:inline-block;margin-right:8px;transition:transform .16s ease}}.raw-alert-details[open] summary{{border-bottom-color:rgba(148,163,184,.14)}}.raw-alert-details[open] summary:before{{transform:rotate(90deg)}}.raw-alert-body{{padding:12px 14px}}.markdown-body h2,.markdown-body h3,.markdown-body h4,.markdown-body h5,.markdown-body h6{{color:#f5f9ff;margin:18px 0 8px}}.markdown-body pre{{overflow:auto;background:#020617;border:1px solid rgba(148,163,184,.18);border-radius:12px;padding:12px}}.table-wrap{{overflow:auto;border:1px solid rgba(148,163,184,.16);border-radius:10px;margin:10px 0}}.empty{{border:1px dashed rgba(148,163,184,.28);border-radius:10px;color:#b9c7da;padding:24px;text-align:center}}.mobile-triage-bar{{display:none}}.severity-chip-row{{display:flex;gap:8px;overflow:auto;padding-bottom:2px;-webkit-overflow-scrolling:touch}}.severity-chip{{flex:0 0 auto;border:1px solid rgba(148,163,184,.16);border-radius:999px;padding:8px 11px;color:#cbd7e7;background:#0b131c;font-size:12px;font-weight:850;cursor:pointer}}.severity-chip.active{{color:#061018;background:linear-gradient(135deg,#22d3ee,#8ff4ff);border-color:transparent;box-shadow:0 0 16px rgba(34,211,238,.24)}}.severity-chip.sev-critical:not(.active){{color:var(--red)}}.severity-chip.sev-high:not(.active){{color:var(--orange)}}.severity-chip.sev-medium:not(.active){{color:var(--amber)}}.severity-chip.sev-low:not(.active){{color:#86efac}}.severity-chip.sev-informational:not(.active){{color:#93c5fd}}.mobile-sort-label{{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:10px;color:#9fb0c4;font-size:12px;font-weight:850}}.mobile-sort-label select{{min-height:38px;border:1px solid rgba(34,211,238,.20);border-radius:10px;padding:0 10px;color:#dce9f8;background:#0b131c;font:inherit}}.mobile-alert-list{{display:none}}.mobile-alert-card{{width:100%;max-width:100%;min-width:0;border:0;border-radius:20px;background:transparent}}.mobile-alert-card[data-acknowledged='true'],.mobile-alert-card[data-suppressed='true']{{opacity:.58}}.mobile-alert-pill{{display:grid;width:100%;max-width:100%;min-width:0;gap:10px;border:1px solid rgba(148,163,184,.14);border-radius:20px;padding:15px 16px;color:inherit;background:linear-gradient(180deg,#0d1620,#0a121b);box-shadow:0 10px 22px rgba(0,0,0,.22),inset 0 1px 0 rgba(255,255,255,.03);text-align:left;cursor:pointer;appearance:none;-webkit-appearance:none}}.mobile-alert-pill:focus-visible{{outline:2px solid rgba(143,244,255,.88);outline-offset:3px}}.mobile-alert-card.mobile-expanded .mobile-alert-pill{{border-color:rgba(34,211,238,.38);border-bottom-left-radius:14px;border-bottom-right-radius:14px;box-shadow:0 0 0 1px rgba(34,211,238,.08),0 12px 28px rgba(0,0,0,.28),inset 0 1px 0 rgba(255,255,255,.04)}}.mobile-card-top,.mobile-card-meta,.mobile-card-actions{{display:flex;align-items:center;justify-content:space-between;gap:10px;min-width:0}}.mobile-card-time,.mobile-card-meta{{color:#91a2b7;font-size:11px}}.mobile-alert-pill strong{{display:block;min-width:0;color:#f2f7ff;font-size:14px;line-height:1.28;overflow-wrap:anywhere}}.mobile-card-summary{{display:block;min-width:0;color:#aeb9c7;font-size:12px;line-height:1.45;overflow-wrap:anywhere}}.mobile-endpoints{{display:grid;gap:7px;min-width:0}}.mobile-endpoints span{{display:flex;align-items:center;justify-content:space-between;gap:10px;min-width:0;color:#8ff4ff;font-size:11px}}.mobile-endpoints code{{min-width:0;max-width:70%;overflow:hidden;text-overflow:ellipsis;color:#dce9f8;background:rgba(148,163,184,.05);border:1px solid rgba(148,163,184,.12);border-radius:999px;padding:5px 8px;font-size:11px;white-space:nowrap}}.mobile-card-meta{{flex-wrap:wrap;justify-content:flex-start}}.mobile-card-meta span{{display:inline-flex;align-items:center;gap:4px;min-width:0}}.mobile-pill-details{{width:100%;max-width:100%;min-width:0;margin-top:8px;border:1px solid rgba(34,211,238,.16);border-radius:16px;padding:12px;background:#071018;box-shadow:inset 0 1px 0 rgba(255,255,255,.025);overflow:hidden}}.mobile-pill-details[hidden]{{display:none!important}}.mobile-pill-details .markdown-body,.mobile-pill-details .api-detail-content{{width:100%;max-width:100%;min-width:0;overflow-wrap:anywhere;word-break:break-word}}.mobile-pill-details .api-detail-grid{{grid-template-columns:1fr}}.mobile-pill-details .markdown-body pre,.mobile-pill-details .api-detail-content pre{{max-width:100%;overflow:auto;white-space:pre-wrap}}.mobile-pill-details .markdown-body table,.mobile-pill-details .api-detail-content table{{display:block;width:100%;max-width:100%;overflow:auto}}.mobile-card-actions{{justify-content:flex-start;flex-wrap:wrap;margin-bottom:12px}}.footer{{color:var(--muted);font-size:12px;margin-top:18px}}@media(max-width:1180px){{.app-shell,.app-shell.sidebar-collapsed{{grid-template-columns:1fr}}.sidebar{{position:fixed;left:0;right:0;bottom:0;top:auto;z-index:120;width:100%;height:72px;display:flex;justify-content:center;padding:8px 10px;border-right:0;border-top:1px solid rgba(34,211,238,.18);background:linear-gradient(180deg,rgba(9,17,26,.82),rgba(9,17,26,.97));backdrop-filter:blur(18px);box-shadow:0 -14px 28px rgba(0,0,0,.35)}}.sidebar .brand,.sidebar .sidebar-bottom{{display:none}}.sidebar .nav{{width:100%;max-width:680px;display:flex;align-items:center;justify-content:space-around;gap:6px;margin:0}}.sidebar .nav-item{{width:54px;height:54px;justify-content:center;padding:0;border-radius:16px}}.sidebar .nav-left{{justify-content:center;gap:0}}.sidebar .nav-label,.sidebar .nav-count{{display:none}}.sidebar .nav-icon,.sidebar .nav-icon svg{{width:26px;height:26px}}.content{{padding-bottom:96px}}.workspace{{grid-template-columns:1fr}}.selected-panel{{position:relative;top:auto}}.topbar{{grid-template-columns:minmax(0,1fr) auto;grid-template-areas:'title avatar' 'search search' 'toggles toggles';gap:12px;padding-bottom:14px}}.app-shell[data-view="overview"] .topbar{{grid-template-areas:'title avatar';grid-template-columns:minmax(0,1fr) auto}}.title{{grid-area:title}}.search-wrap{{grid-area:search}}.toggle-refresh-group{{grid-area:toggles;display:flex;align-items:center;gap:12px;justify-content:start;flex-wrap:wrap}}.time-filter{{min-width:188px}}.toggle-stack{{grid-template-columns:repeat(2,max-content);gap:10px 16px;justify-content:start}}.avatar{{grid-area:avatar;justify-self:end}}.flow-hero{{grid-template-columns:1fr}}.network-diagram{{grid-template-columns:1fr;grid-template-rows:auto;min-height:0}}.node-so,.node-pi,.node-mac,.link-one,.link-two,.flow-fanout,.output-dashboard,.output-markdown,.output-ai,.output-phone{{grid-column:1;grid-row:auto}}.flow-link{{height:44px;width:2px;justify-self:center;background:linear-gradient(180deg,rgba(34,211,238,.22),rgba(143,244,255,.92),rgba(34,211,238,.22))}}.flow-link:after{{right:50%;top:auto;bottom:-2px;transform:translateX(50%) rotate(135deg)}}.flow-link span{{top:50%;left:calc(50% + 16px);transform:translateY(-50%)}}.flow-fanout{{display:none}}.overview-status{{grid-template-columns:repeat(2,minmax(0,1fr))}}.metrics{{grid-template-columns:repeat(2,minmax(0,1fr))}}.metrics.verbose-metrics{{grid-template-columns:1fr}}}}@media(max-width:700px){{body{{background:#071018}}.content{{padding:14px 10px 92px}}.topbar{{top:0;width:auto;max-width:none;min-width:0;margin:-14px -10px 12px;padding:14px 10px 12px;border-bottom:1px solid rgba(148,163,184,.10);grid-template-columns:minmax(0,1fr);grid-template-areas:'title'}}.app-shell[data-view="overview"] .topbar{{grid-template-columns:minmax(0,1fr);grid-template-areas:'title'}}.title{{grid-area:title}}.avatar{{display:none}}.title-row{{justify-content:space-between;min-width:0}}.mobile-controls-toggle{{display:inline-flex;flex:0 0 40px}}.search-wrap.alerts-only,.toggle-refresh-group.alerts-only{{display:none}}.app-shell.mobile-menu-open .topbar{{grid-template-areas:'title' 'search' 'toggles'}}.app-shell.mobile-menu-open .search-wrap.alerts-only{{display:block;grid-area:search}}.app-shell.mobile-menu-open .toggle-refresh-group.alerts-only{{display:grid;grid-area:toggles;grid-template-columns:minmax(0,1fr) minmax(0,1fr) auto;justify-content:flex-start;align-items:end;width:100%;gap:8px}}.app-shell.mobile-menu-open .toggle-stack{{grid-column:1 / -1;grid-template-columns:repeat(2,minmax(0,max-content));gap:8px 12px}}.app-shell.mobile-menu-open .toggle-refresh-group .time-filter{{flex:none;width:auto;max-width:100%}}.app-shell.mobile-menu-open .last-seen-filter,.app-shell.mobile-menu-open .sort-default-filter{{width:auto}}.title,.search-wrap,.toggle-refresh-group{{min-width:0;max-width:100%}}.title h1{{font-size:25px}}.alerts-refresh{{width:38px;height:38px;min-width:38px;min-height:38px;border-radius:15px}}.alerts-refresh:before{{border-radius:13px}}.alerts-refresh-icon{{font-size:23px}}.subtitle{{display:none}}.search{{min-height:44px;border-radius:12px}}.toggle-stack{{grid-template-columns:1fr;gap:8px}}.time-filter{{min-width:0;flex:1 1 190px}}.toggle-wrap{{font-size:12px}}.flow-hero{{padding:14px;border-radius:12px}}.flow-copy h2{{font-size:28px}}.network-diagram{{padding:12px}}.flow-node{{min-height:112px}}.overview-status{{grid-template-columns:1fr}}.metrics,.metrics.verbose-metrics{{grid-template-columns:1fr;gap:10px}}.metric-card{{min-height:82px;padding:13px 14px;border-radius:14px}}.metric-icon{{width:50px;height:50px;flex-basis:50px;border-radius:14px}}.metric-icon img{{width:44px;height:44px}}.metric-extra{{min-width:0;max-width:52%;padding-left:9px}}.severity-breakdown{{grid-template-columns:repeat(2,max-content);gap:3px 6px}}.sev-chip{{font-size:10px}}.metric-detail-row{{font-size:10px;gap:7px}}.metric-detail-row span{{max-width:118px}}.mobile-triage-bar{{display:block;margin-bottom:10px}}.mobile-alert-list{{display:grid;gap:10px;width:100%;max-width:100%;overflow:hidden}}#suppress-modal{{top:var(--suppress-vv-offset-top,0px);bottom:auto;height:var(--suppress-vv-height,100dvh);min-height:0;width:100vw;padding:max(10px,env(safe-area-inset-top)) 12px max(10px,env(safe-area-inset-bottom));align-items:center;overflow:hidden}}#suppress-modal .modal-card{{width:min(100%,calc(100vw - 24px));max-height:calc(var(--suppress-vv-height,100dvh) - 24px);padding:16px 14px;border-radius:14px;overscroll-behavior:contain}}#suppress-modal .modal-card h2{{font-size:22px}}#suppress-modal .modal-card p{{font-size:15px;line-height:1.45}}.suppression-network-context{{font-size:13px;line-height:1.35;white-space:normal}}#suppress-modal .modal-card textarea{{font-size:16px;line-height:1.45;min-height:132px;max-height:34dvh}}#suppress-modal .modal-meta{{flex-wrap:wrap;gap:8px;font-size:13px}}#suppress-modal .modal-actions{{width:100%;display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.35fr);gap:9px}}#suppress-modal .modal-actions .modal-button{{min-height:46px;padding:10px 12px;font-size:15px}}.table-card{{display:none;border-radius:14px;margin:0 -2px;max-height:none;-webkit-overflow-scrolling:touch}}.alert-table{{min-width:980px}}th{{padding:11px 10px;font-size:10px}}td{{padding:10px;font-size:12px}}.alert-cell strong{{font-size:12px}}.endpoint-cell code{{font-size:11px;padding:4px 6px}}.ack-button{{padding:8px 10px}}.detail-template{{padding:14px;border-radius:12px}}.pinned-alert-viewport{{border-radius:0 0 12px 12px}}.pinned-alert-cell{{padding:10px;font-size:12px}}.sidebar{{height:66px;padding:7px 8px}}.sidebar .nav{{justify-content:flex-start;overflow-x:auto;overflow-y:hidden;scroll-snap-type:x proximity;-webkit-overflow-scrolling:touch;padding:0 4px}}.sidebar .nav-item{{width:48px;height:48px;flex:0 0 48px;border-radius:15px;scroll-snap-align:center}}.sidebar .nav-icon,.sidebar .nav-icon svg{{width:24px;height:24px}}}}@media(max-width:420px){{.avatar{{display:none}}.topbar{{grid-template-columns:minmax(0,1fr);grid-template-areas:'title' 'search' 'toggles'}}.app-shell[data-view="overview"] .topbar{{grid-template-areas:'title';grid-template-columns:minmax(0,1fr)}}.subtitle{{display:none}}.toggle-refresh-group{{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr) auto;justify-content:flex-start;align-items:end;width:100%;gap:8px}}.app-shell.mobile-menu-open .toggle-refresh-group.alerts-only{{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr) auto;justify-content:flex-start;align-items:end;width:100%;gap:8px}}.toggle-stack{{grid-column:1 / -1;grid-template-columns:repeat(2,minmax(0,max-content));gap:8px 12px}}.toggle-refresh-group .time-filter{{flex:none;width:auto;max-width:100%}}.last-seen-filter,.sort-default-filter{{width:auto}}.metric-main{{min-width:64px}}.metric-extra{{max-width:58%}}.alert-table{{min-width:940px}}}}
</style><link rel="stylesheet" href="assets/dashboard-metrics.css?v=20260707-metric-card-spacing"></head><body><div class="app-shell" data-view="overview"><aside class="sidebar" aria-label="Onion Sentinel navigation"><div class="brand"><button id="sidebar-toggle" class="brand-shield logo-toggle" type="button" aria-label="Collapse sidebar" aria-expanded="true" title="Collapse sidebar"><img class="brand-logo" src="assets/onion-sentinel-logo.png" alt="Onion Sentinel logo"></button><span class="brand-text">Onion <span>Sentinel</span></span></div>{build_nav_html('home', active_count)}<div class="sidebar-bottom"><div class="health" id="system-health-tile" data-health-state="unknown"><b>System Health</b><span><i class="status-dot"></i><span id="system-health-text">Checking n8n beacon...</span></span></div><div class="analyst byline"><span>by <a href="https://www.linkedin.com/in/arronjablonowski" target="_blank" rel="noopener noreferrer">Arron Jablonowski</a></span></div></div></aside><main class="content" id="top"><header class="topbar" aria-label="SOC alert controls"><div class="title"><div class="title-row"><h1 id="page-title">SOC Overview</h1><button id="mobile-controls-toggle" class="mobile-controls-toggle alerts-only" type="button" aria-label="Open alert controls" aria-expanded="false" title="Alert controls"><span></span><span></span><span></span></button></div><div id="page-subtitle" class="subtitle">Autonomous SIEM alert enrichment data flow</div></div><div class="search-wrap alerts-only"><input id="search" class="search" type="search" placeholder="Search alerts..."><span class="kbd">⌘K</span></div><div class="toggle-refresh-group alerts-only"><div class="toggle-stack"><label class="toggle-wrap"><input id="show-acknowledged" type="checkbox"><span class="toggle-slider"></span><span>Show acknowledged</span></label><label class="toggle-wrap"><input id="show-suppressed" type="checkbox"><span class="toggle-slider"></span><span>Show suppressed</span></label></div><label class="time-filter last-seen-filter"><span>Last Seen</span><select id="last-seen-window" aria-label="Filter alerts by last seen time"><option value="all">All time</option><option value="30">Last 30 min</option><option value="60">Last 1 hour</option><option value="120">Last 2 hours</option><option value="180">Last 3 hours</option><option value="240">Last 4 hours</option><option value="300">Last 5 hours</option><option value="360">Last 6 hours</option><option value="720">Last 12 hours</option><option value="1440">Last 24 hours</option><option value="2160">Last 36 hours</option><option value="4320">Last 72 hours</option><option value="10080">Last 7 days</option></select></label><label class="time-filter sort-default-filter"><span>Sorting Default</span><select id="sorting-default" aria-label="Choose default alert table sorting"><option value="last_seen">Newest Alerts First</option><option value="severity">Highest Severity First</option></select></label><button id="alerts-refresh" class="alerts-refresh" type="button" aria-label="Refresh SOC Alerts table" title="Refresh SOC Alerts table" aria-busy="false"><span class="alerts-refresh-icon" aria-hidden="true">↻</span></button></div><div class="avatar"><div class="avatar-bubble">SO</div><span>⌄</span></div></header>{overview_html}<section id="alerts-view" class="view-section alerts-view" aria-label="SOC alert table"><section class="metrics" aria-label="SOC alert report metrics">{soc_metrics_html}</section><div id="pinned-alert-viewport" class="pinned-alert-viewport" aria-hidden="true"><div id="pinned-alert-row" class="pinned-alert-row"></div></div><section class="workspace" aria-label="SOC alert workspace">{table_html}</section></section><div class="footer">Generated {html.escape(now)} from {html.escape(str(DB_PATH).replace(str(HOME), '~'))}; Markdown corpus remains {html.escape(str(SOURCE_DIR).replace(str(HOME), '~'))}.</div></main></div><div id="suppress-modal" class="modal-backdrop" hidden><div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="suppress-modal-title"><h2 id="suppress-modal-title">Suppress alert</h2><p>Enter a short reason. This will hide the current detection and matching future detections until it is exposed again.</p><div id="suppress-network-context" class="suppression-network-context" hidden></div><textarea id="suppress-reason" maxlength="140" placeholder="Reason for suppression"></textarea><div class="modal-meta"><span>Suppression reason is saved with this alert.</span><span id="suppress-char-count">0 / 140</span></div><div class="modal-actions"><button id="cancel-suppression" class="modal-button" type="button">Cancel</button><button id="confirm-suppression" class="modal-button primary" type="button" disabled>Confirm Suppression</button></div></div></div><script>
(() => {{
let search=document.querySelector('#search'),showAcknowledged=document.querySelector('#show-acknowledged'),showSuppressed=document.querySelector('#show-suppressed'),lastSeenWindow=document.querySelector('#last-seen-window'),sortingDefault=document.querySelector('#sorting-default'),visibleCount=document.querySelector('#visible-count'),navVisibleCount=document.querySelector('#soc-alerts-nav-count'),socRefreshButton=document.querySelector('#alerts-refresh'),mobileControlsToggle=document.querySelector('#mobile-controls-toggle'),topbar=document.querySelector('.topbar'),tableCard=document.querySelector('.table-card'),pinnedViewport=document.querySelector('#pinned-alert-viewport'),pinnedRow=document.querySelector('#pinned-alert-row'),appShell=document.querySelector('.app-shell'),sidebarToggle=document.querySelector('#sidebar-toggle'),pageTitle=document.querySelector('#page-title'),pageSubtitle=document.querySelector('#page-subtitle'),viewButtons=[...document.querySelectorAll('[data-view-target]')],viewSections=[...document.querySelectorAll('.view-section')],groups=[...document.querySelectorAll('.report-row-group')],mobileCards=[...document.querySelectorAll('.mobile-alert-card')],severityFilterButtons=[...document.querySelectorAll('[data-severity-filter]')],sortHeaders=[...document.querySelectorAll('[data-sort-key]')],mobileSort=document.querySelector('#mobile-sort'),suppressModal=document.querySelector('#suppress-modal'),suppressReasonInput=document.querySelector('#suppress-reason'),suppressNetworkContext=document.querySelector('#suppress-network-context'),suppressCharCount=document.querySelector('#suppress-char-count'),confirmSuppressionButton=document.querySelector('#confirm-suppression'),cancelSuppressionButton=document.querySelector('#cancel-suppression'),statusStorageKey='soc-alerts-triage-status-v2',legacyAckStorageKey='soc-alerts-acknowledged-v1',sidebarStorageKey='soc-alerts-sidebar-collapsed-v1',sortDefaultStorageKey='soc-alerts-sort-default-v1';let selectedGroup=null,severityFilter='all',apiSortKey='last_seen',apiSortDirection='desc',pendingSuppressGroup=null,pendingStatusUpdate=null;function pad2(value){{return String(value).padStart(2,'0')}}function localOffset(date){{const minutes=-date.getTimezoneOffset(),sign=minutes>=0?'+':'-',absolute=Math.abs(minutes);return `${{sign}}${{pad2(Math.floor(absolute/60))}}:${{pad2(absolute%60)}}`}}function formatDateAsProjectIso(date){{const ms=date.getMilliseconds(),fraction=ms?`.${{String(ms).padStart(3,'0')}}`:'';return `${{date.getFullYear()}}-${{pad2(date.getMonth()+1)}}-${{pad2(date.getDate())}}  ${{pad2(date.getHours())}}:${{pad2(date.getMinutes())}}:${{pad2(date.getSeconds())}}${{fraction}}${{localOffset(date)}}`}}function parseProjectDate(value){{const text=String(value||'').trim();if(!text)return null;const parseable=text.replace(/(\d{{4}}-\d{{2}}-\d{{2}})(?:T|\s+)(?=\d{{2}}:\d{{2}}:\d{{2}})/,'$1T');const hasOffset=/(?:Z|[+-]\d{{2}}:?\d{{2}})$/.test(parseable);const date=new Date(hasOffset?parseable:`${{parseable}}Z`);return Number.isFinite(date.getTime())?date:null}}function formatProjectIso(value){{const date=parseProjectDate(value);if(date)return formatDateAsProjectIso(date);return String(value||'').trim().replace(/(\d{{4}}-\d{{2}}-\d{{2}})(?:T|\s+)(?=\d{{2}}:\d{{2}}:\d{{2}})/,'$1  ')}}function formatLocalIsoFromUtc(value){{return formatProjectIso(value)}}function projectNowIso(){{return formatDateAsProjectIso(new Date())}}function renderLocalLastSeen(){{document.querySelectorAll('[data-last-seen-utc]').forEach(element=>{{const raw=element.dataset.lastSeenUtc||element.textContent;const normalized=formatProjectIso(raw);element.textContent=normalized;element.setAttribute('title',normalized)}})}}function setView(view){{const normalized=view==='alerts'?'alerts':'overview';if(appShell)appShell.dataset.view=normalized;viewSections.forEach(section=>section.classList.toggle('active',section.id===`${{normalized}}-view`));viewButtons.forEach(button=>button.classList.toggle('active',button.dataset.viewTarget===normalized));if(pageTitle)pageTitle.textContent=normalized==='alerts'?'SOC Alerts':'SOC Overview';if(pageSubtitle)pageSubtitle.textContent=normalized==='alerts'?'AI-powered triage and investigation':'Autonomous SIEM alert enrichment data flow';if(normalized!=='alerts')pinnedViewport?.classList.remove('visible');setTimeout(updatePinnedRow,80)}}function setSidebarCollapsed(collapsed){{appShell?.classList.toggle('sidebar-collapsed',collapsed);if(sidebarToggle){{sidebarToggle.setAttribute('aria-expanded',String(!collapsed));sidebarToggle.setAttribute('aria-label',collapsed?'Expand sidebar':'Collapse sidebar');sidebarToggle.setAttribute('title',collapsed?'Expand sidebar':'Collapse sidebar')}}try{{localStorage.setItem(sidebarStorageKey,collapsed?'1':'0')}}catch(_){{}}setTimeout(updatePinnedRow,210)}}function currentRepeatCount(group){{return Number(group?.dataset.repeatCount||0)||0}}function normalizeStatusMeta(meta){{if(!meta||typeof meta!=='object')return null;const status=String(meta.status||'open').toLowerCase();if(!['open','acknowledged','suppressed'].includes(status))return null;return {{status,repeat_count:Number(meta.repeat_count||meta.acknowledged_count||0)||0,reason:String(meta.reason||'').slice(0,140),updated_at:meta.updated_at||null}}}}function loadStoredStatuses(){{const statuses={{}};try{{const parsed=JSON.parse(localStorage.getItem(statusStorageKey)||'{{}}');if(parsed&&typeof parsed==='object'){{Object.entries(parsed).forEach(([id,meta])=>{{const normalized=normalizeStatusMeta(meta);if(normalized&&normalized.status!=='open')statuses[id]=normalized}})}}}}catch(_){{}}try{{const legacy=JSON.parse(localStorage.getItem(legacyAckStorageKey)||'[]');if(Array.isArray(legacy))legacy.forEach(id=>{{if(!statuses[id])statuses[id]={{status:'acknowledged',repeat_count:0,updated_at:null}}}})}}catch(_){{}}return statuses}}let alertStatuses={{}};function statusForGroup(group){{const id=group?.dataset.reportId,meta=alertStatuses[id];if(!id||!meta)return {{status:'open',repeat_count:0}};if(meta.status==='acknowledged'&&currentRepeatCount(group)>Number(meta.repeat_count||0)){{delete alertStatuses[id];persistStatusesLocally();return {{status:'open',repeat_count:0}}}}return meta}}function persistStatusesLocally(){{try{{localStorage.setItem(statusStorageKey,JSON.stringify(alertStatuses));localStorage.removeItem(legacyAckStorageKey)}}catch(_){{}}}}function saveStatuses(){{persistStatusesLocally();if(!pendingStatusUpdate)return;fetch('/api/soc-alerts/status',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(pendingStatusUpdate)}}).then(r=>r.ok?r.json():null).then(data=>{{pendingStatusUpdate=null;if(data&&data.statuses){{mergeServerStatuses(data.statuses);hydrateTriageStatuses();applyFilter()}}}}).catch(()=>{{pendingStatusUpdate=null}})}}function mergeServerStatuses(statuses){{const next={{}};Object.entries(statuses||{{}}).forEach(([id,meta])=>{{const normalized=normalizeStatusMeta(meta);if(normalized&&normalized.status!=='open')next[id]=normalized}});alertStatuses=next;persistStatusesLocally()}}async function loadServerStatuses(){{try{{const response=await fetch('/api/soc-alerts/status',{{cache:'no-store'}});if(!response.ok)return;const data=await response.json();if(!data||!data.statuses)return;mergeServerStatuses(data.statuses);hydrateTriageStatuses();applyFilter()}}catch(_){{}}}}function setAiStatusPill(pill,status){{if(!pill||!status)return;const key=status.ai_status_key||'queued',label=status.ai_status_label||'Queued',detail=status.ai_status_detail||'';pill.className=`ai-status-pill ai-status-${{key}}`;pill.textContent=label;pill.title=detail}}function renderAiActivityExtra(counts,model){{const active=Number(counts?.analyzing||0),queued=Number(counts?.queued||0),analyzed=Number(counts?.analyzed||0),skipped=Number(counts?.not_queued||counts?.skipped||0),safeModel=String(model||'devstral:latest').replace(/[&<>]/g,char=>({{'&':'&amp;','<':'&lt;','>':'&gt;'}}[char]));return `<span class="metric-detail-row"><b>Model</b><span>${{safeModel}}</span></span><span class="metric-detail-row"><b>Active</b><span>${{active}}</span></span><span class="metric-detail-row"><b>Queued</b><span>${{queued}}</span></span><span class="metric-detail-row"><b>Analyzed</b><span>${{analyzed}}</span></span><span class="metric-detail-row"><b>Skipped</b><span>${{skipped}}</span></span>`}}function updateAiActivityCounts(counts){{const set=(id,value)=>{{const el=document.querySelector(id);if(el)el.textContent=String(Number(value||0))}};set('#ai-analyzed-count',counts?.analyzed);set('#ai-queued-count',counts?.queued);set('#ai-skipped-count',counts?.not_queued??counts?.skipped)}}function renderBeaconExtra(beacon){{const esc=value=>String(value??'—').replace(/[&<>]/g,char=>({{'&':'&amp;','<':'&lt;','>':'&gt;'}}[char]));const alert=beacon.rule_name||beacon.alert_id||'Webhook received';const source=[beacon.source_ip,beacon.destination_ip].filter(Boolean).join(' -> ')||'n8n webhook';const status=beacon.status||beacon.stage||'received';return `<span class="metric-detail-row"><b>Alert</b><span>${{esc(alert)}}</span></span><span class="metric-detail-row"><b>Source</b><span>${{esc(source)}}</span></span><span class="metric-detail-row"><b>Status</b><span>${{esc(status)}}</span></span>`}}async function pollN8nBeacon(){{try{{const response=await fetch('n8n-beacon.json?ts='+Date.now(),{{cache:'no-store'}});if(!response.ok)return;const beacon=await response.json();updateN8nBeaconFromPayload(beacon)}}catch(_){{}}}}function beaconEpochMs(value){{if(!value)return NaN;const normalized=String(value).replace(/(\d{{4}}-\d{{2}}-\d{{2}})(?:T|\s+)(?=\d{{2}}:\d{{2}}:\d{{2}})/,'$1T');const parsed=Date.parse(normalized);return Number.isFinite(parsed)?parsed:NaN}}function updateSystemHealthFromBeacon(beacon){{const tile=document.querySelector('#system-health-tile'),label=document.querySelector('#system-health-text');if(!tile||!label)return;const timestamp=beacon?.generated_at||beacon?.last_seen||beacon?.timestamp,epoch=beaconEpochMs(timestamp),ageMs=Number.isFinite(epoch)?Date.now()-epoch:NaN,ok=Number.isFinite(ageMs)&&ageMs>=0&&ageMs<=20*60*1000;tile.dataset.healthState=ok?'ok':'stale';label.textContent=ok?'n8n beacon healthy':'n8n beacon stale';tile.title=Number.isFinite(ageMs)?`Last n8n beacon ${{Math.max(0,Math.round(ageMs/60000))}} minutes ago`:'No valid n8n beacon timestamp'}}function updateN8nBeaconFromPayload(beacon){{const time=document.querySelector('#n8n-beacon-time'),extra=document.querySelector('#n8n-beacon-extra');if(time&&beacon?.generated_at)time.textContent=formatLocalIsoFromUtc(beacon.generated_at);if(extra&&beacon)extra.innerHTML=renderBeaconExtra(beacon);updateSystemHealthFromBeacon(beacon)}}function updateLatestAlertMetric(metrics){{if(!metrics)return;const pcapIngest=document.querySelector('#pcap-ingest-size');if(pcapIngest)pcapIngest.textContent=formatApiBytes(metrics.pcap_ingest_size_bytes||0);if(!metrics.latest_seen)return;const time=document.querySelector('#latest-alert-time'),extra=document.querySelector('#latest-alert-extra'),card=document.querySelector('#latest-alert-card');if(time)time.textContent=formatLocalIsoFromUtc(metrics.latest_seen);if(extra)extra.innerHTML=`<span class="metric-detail-row"><b>Groups</b><span>${{Number(metrics.grouped_total||0)}}</span></span><span class="metric-detail-row"><b>Observations</b><span>${{Number(metrics.grouped_observations||metrics.total||0)}}</span></span>`;}}async function pollSocAlertMetrics(){{try{{const response=await fetch('/api/soc-alerts/metrics?since=7d&ts='+Date.now(),{{cache:'no-store'}});if(!response.ok)return;const metrics=await response.json();updateLatestAlertMetric(metrics)}}catch(_){{}}}}function statusPayloadAlertCount(data){{const open=Number(data?.counts?.open);if(Number.isFinite(open))return open;const total=Number(data?.counts?.total);const acknowledged=Number(data?.counts?.acknowledged||0),suppressed=Number(data?.counts?.suppressed||0);if(Number.isFinite(total))return Math.max(0,total-acknowledged-suppressed);return Number.NaN}}function setActiveAlertCount(count){{const active=Number(count);if(!Number.isFinite(active))return;if(navVisibleCount)navVisibleCount.textContent=String(active);document.querySelectorAll('#api-visible-total,#top-api-visible-total,#visible-count').forEach(el=>el.textContent=String(active))}}function updateNavAlertCountFromStatus(data){{const count=statusPayloadAlertCount(data);if(!Number.isFinite(count))return;setActiveAlertCount(count)}}function updateAiStatusFromPayload(data){{if(!data||!data.ai)return;updateNavAlertCountFromStatus(data);const aiCard=document.querySelector('#ai-activity-card'),aiLabel=document.querySelector('#ai-activity-label'),aiDetail=document.querySelector('#ai-activity-detail'),aiExtra=document.querySelector('#ai-activity-extra');aiCard?.classList.toggle('ai-activity-active',Boolean(data.ai.active));if(aiLabel)aiLabel.textContent=data.ai.label||'AI Alert Triage';if(aiDetail)aiDetail.textContent=data.ai.detail||`Model: ${{data.ai.model||'devstral:latest'}}`;if(aiExtra)aiExtra.innerHTML=renderAiActivityExtra(data.ai.counts||{{}},data.ai.model);updateAiActivityCounts(data.ai.counts||{{}});Object.entries(data.reports||{{}}).forEach(([id,status])=>{{const selectorId=CSS.escape(id);document.querySelectorAll(`.report-row-group[data-report-id="${{selectorId}}"]`).forEach(group=>{{group.dataset.aiStatus=status.ai_status_key||'queued';setAiStatusPill(group.querySelector('.ai-status-cell .ai-status-pill'),status)}});document.querySelectorAll(`[data-mobile-report-id="${{selectorId}}"] .ai-status-pill`).forEach(pill=>setAiStatusPill(pill,status))}});if(selectedGroup)syncPinnedContent(selectedGroup);updatePinnedRow()}}function socEventsTableSignature(data){{return JSON.stringify({{counts:data?.counts||{{}},metrics:{{grouped_total:data?.metrics?.grouped_total,total:data?.metrics?.total,latest_seen:data?.metrics?.latest_seen}},ai:data?.ai?.counts||{{}},beacon:data?.beacon?.generated_at||''}})}}function scheduleSocEventApiReload(){{if(appShell?.dataset.view!=='alerts'||!socApiTableEnabled)return;clearTimeout(socEventsReloadTimer);socEventsReloadTimer=setTimeout(()=>loadApiAlerts(true),650)}}function handleSocEventPayload(data){{if(!data||!data.ok)return;if(data.statuses){{mergeServerStatuses(data.statuses);hydrateTriageStatuses();applyFilter()}}if(data.ai)updateAiStatusFromPayload(data);if(data.metrics)updateLatestAlertMetric(data.metrics);if(data.beacon)updateN8nBeaconFromPayload(data.beacon);const nextSignature=socEventsTableSignature(data);if(socEventsSignature&&nextSignature!==socEventsSignature)scheduleSocEventApiReload();socEventsSignature=nextSignature}}function connectSocAlertEvents(){{if(!window.EventSource)return false;try{{socEventsSource?.close();socEventsSource=new EventSource('/api/soc-alerts/events');window.__socEventsConnected=false;socEventsSource.addEventListener('open',()=>{{window.__socEventsConnected=true}});socEventsSource.addEventListener('soc-alerts',event=>{{window.__socEventsConnected=true;try{{handleSocEventPayload(JSON.parse(event.data))}}catch(_){{}}}});socEventsSource.onerror=()=>{{window.__socEventsConnected=false;socEventsSource?.close();socEventsSource=null;setTimeout(connectSocAlertEvents,5000)}};return true}}catch(_){{window.__socEventsConnected=false;return false}}}}async function pollSocAlertStatus(){{try{{const response=await fetch('soc-alerts-status.json?ts='+Date.now(),{{cache:'no-store'}});if(!response.ok)return;const data=await response.json();updateAiStatusFromPayload(data)}}catch(_){{}}}}function severityLabel(level){{return ({{critical:'Crit',high:'High',medium:'Med',low:'Low',informational:'Info',info:'Info'}})[level]||level.charAt(0).toUpperCase()+level.slice(1)}}function buildSeverityBreakdownFromCounts(counts){{const levels=['critical','high','medium','low','informational'];const source=counts||{{}};return levels.map(level=>{{const value=Number(source[level]||0);return `<span class="sev-chip sev-${{level}}${{value===0?' sev-zero':''}}"><b>${{value}}</b> ${{severityLabel(level)}}</span>`}}).join('')}}function buildSeverityBreakdown(groupsToCount){{const levels=['critical','high','medium','low','informational'],counts=Object.fromEntries(levels.map(level=>[level,0]));groupsToCount.forEach(group=>{{const level=group.dataset.criticality||'informational';counts[level]=(counts[level]||0)+1}});return buildSeverityBreakdownFromCounts(counts)}}function setVerboseMode(enabled){{document.querySelector('.metrics')?.classList.toggle('verbose-metrics',enabled)}}function stickyTop(){{const rect=topbar?.getBoundingClientRect();const top=Math.ceil(rect?.height||76);document.documentElement.style.setProperty('--sticky-row-top',`${{top}}px`);return top}}function updateDetailViewport(){{if(!tableCard)return;const visibleWidth=Math.max(320,Math.floor(tableCard.clientWidth-36)),offset=Math.max(0,Math.floor(tableCard.scrollLeft));document.querySelectorAll('.report-row-group.expanded .detail-template').forEach(detail=>{{detail.style.setProperty('--detail-visible-width',`${{visibleWidth}}px`);detail.style.setProperty('--detail-visible-x',`${{offset}}px`)}})}}function syncPinnedContent(group){{if(!pinnedRow||!group)return;const row=group.querySelector('.report-row');const visibleCells=[...row.children].filter(cell=>getComputedStyle(cell).display!=='none');pinnedRow.innerHTML=visibleCells.map(cell=>`<div class="pinned-alert-cell ${{cell.className||''}}">${{cell.innerHTML}}</div>`).join('')}}function updatePinnedRow(){{if(!pinnedRow||!pinnedViewport||appShell?.dataset.view!=='alerts')return;const group=selectedGroup;if(!group||!group.classList.contains('expanded')||getComputedStyle(group).display==='none'){{pinnedViewport.classList.remove('visible');return}}const row=group.querySelector('.report-row'),detail=group.querySelector('.detail-template-row'),table=tableCard?.querySelector('.alert-table');if(!row||!detail||!tableCard||!table){{pinnedViewport.classList.remove('visible');return}}const top=stickyTop();const rowRect=row.getBoundingClientRect(),detailRect=detail.getBoundingClientRect(),cardRect=tableCard.getBoundingClientRect();const withinReport=rowRect.top<=top&&detailRect.bottom>top+rowRect.height+16;if(withinReport){{syncPinnedContent(group);pinnedViewport.style.left=`${{Math.max(0,cardRect.left)}}px`;pinnedViewport.style.width=`${{Math.max(0,cardRect.width)}}px`;pinnedViewport.style.top=`${{top}}px`;pinnedRow.style.width=`${{Math.max(table.scrollWidth,cardRect.width)}}px`;pinnedRow.style.transform=`translateX(${{-tableCard.scrollLeft}}px)`;pinnedViewport.classList.add('visible')}}else{{pinnedViewport.classList.remove('visible')}}}}function scrollPinnedRowIntoPlace(group){{const row=group?.querySelector('.report-row');if(!row)return;const top=stickyTop();const target=window.scrollY+row.getBoundingClientRect().top-top;window.scrollTo({{top:Math.max(0,target),behavior:'smooth'}});setTimeout(updatePinnedRow,180);setTimeout(updatePinnedRow,520)}}function visibleGroups(){{return groups.filter(g=>getComputedStyle(g).display!=='none')}}function sortMobileCards(){{const list=document.querySelector('.mobile-alert-list');if(!list||!mobileSort)return;const mode=mobileSort.value;const byId=new Map(groups.map(g=>[g.dataset.reportId,g]));mobileCards.sort((a,b)=>{{const ga=byId.get(a.dataset.mobileReportId),gb=byId.get(b.dataset.mobileReportId);if(!ga||!gb)return 0;if(mode==='newest')return Number(gb.dataset.mtime||0)-Number(ga.dataset.mtime||0);if(mode==='risk')return Number(gb.dataset.riskScore||0)-Number(ga.dataset.riskScore||0);const rank={{critical:5,high:4,medium:3,low:2,informational:1}};return (rank[gb.dataset.criticality]||0)-(rank[ga.dataset.criticality]||0)||Number(gb.dataset.mtime||0)-Number(ga.dataset.mtime||0)}});mobileCards.forEach(card=>list.appendChild(card))}}function collapseGroup(group){{if(!group)return;group.classList.remove('expanded');group.querySelector('.report-row')?.classList.remove('selected');group.querySelector('.report-row')?.setAttribute('aria-selected','false');if(selectedGroup===group){{pinnedViewport?.classList.remove('visible')}}}}async function loadGroupDetail(group){{const id=group?.dataset.reportId;if(!id)return;const targets=[...group.querySelectorAll('.api-detail-content'),...document.querySelectorAll(`[data-mobile-report-id="${{CSS.escape(id)}}"] .api-detail-content`)];if(!targets.length||targets.every(target=>target.dataset.detailLoaded==='true'||target.dataset.detailLoading==='true'))return;targets.forEach(target=>{{target.dataset.detailLoading='true';target.insertAdjacentHTML('afterbegin','<p class="api-detail-loading">Loading full Detailed Alert Report...</p>')}});try{{const response=await fetch(`/api/soc-alerts/${{encodeURIComponent(id)}}/detail`,{{cache:'no-store'}});if(!response.ok)throw new Error(`HTTP ${{response.status}}`);const data=await response.json();if(!data.ok||!data.detail_html)throw new Error(data.error||'Detail unavailable');targets.forEach(target=>{{target.innerHTML=data.detail_html;target.dataset.detailLoaded='true';delete target.dataset.detailLoading}});hydrateTriageStatuses();renderLocalLastSeen();updateDetailViewport();if(group===selectedGroup)syncPinnedContent(group)}}catch(error){{targets.forEach(target=>{{target.dataset.detailLoading='false';target.querySelector('.api-detail-loading')?.remove();target.insertAdjacentHTML('afterbegin',`<p class="api-detail-error">Full detail load failed: ${{escapeHtml(error.message||error)}}</p>`)}})}}}}
function expandGroup(group){{if(!group)return;loadGroupDetail(group);if(selectedGroup&&selectedGroup!==group)collapseGroup(selectedGroup);selectedGroup=group;stickyTop();group.classList.add('expanded');updateDetailViewport();group.querySelector('.report-row')?.classList.add('selected');group.querySelector('.report-row')?.setAttribute('aria-selected','true');syncPinnedContent(group);requestAnimationFrame(()=>scrollPinnedRowIntoPlace(group))}}function toggleGroup(group){{if(group?.classList.contains('expanded')){{collapseGroup(group);if(selectedGroup===group)selectedGroup=null;updatePinnedRow()}}else{{expandGroup(group)}}}}function escapeHtml(value){{return String(value??'').replace(/[&<>"']/g,char=>({{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}}[char]))}}async function setTriageStatus(group,status,reason=''){{const id=group?.dataset.reportId;if(!id)return;const cleanReason=String(reason||'').trim().slice(0,140),repeatCount=currentRepeatCount(group),previousStatus=alertStatuses[id]||null;if(status==='open')delete alertStatuses[id];else alertStatuses[id]={{status,repeat_count:repeatCount,reason:cleanReason,updated_at:projectNowIso()}};hydrateTriageStatuses();applyFilter();try{{const response=await fetch(`/api/soc-alerts/${{encodeURIComponent(id)}}/ack`,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{status,repeat_count:repeatCount,reason:cleanReason}})}});if(!response.ok)throw new Error(`HTTP ${{response.status}}`);const data=await response.json();if(data&&data.statuses)mergeServerStatuses(data.statuses);hydrateTriageStatuses();applyFilter();if(socApiTableEnabled)loadApiAlerts(true)}}catch(error){{if(previousStatus)alertStatuses[id]=previousStatus;else delete alertStatuses[id];hydrateTriageStatuses();applyFilter();loadServerStatuses();if(socApiTableEnabled)loadApiAlerts(true);console.error('SOC alert status update failed',error)}}}}function hydrateTriageStatuses(){{groups.forEach(group=>{{const id=group.dataset.reportId,meta=statusForGroup(group),isAck=meta.status==='acknowledged',isSuppressed=meta.status==='suppressed';group.dataset.acknowledged=isAck?'true':'false';group.dataset.suppressed=isSuppressed?'true':'false';document.querySelectorAll(`[data-acknowledge="${{CSS.escape(id)}}"]`).forEach(button=>button.textContent=isAck?'Unacknowledge':'Acknowledge');document.querySelectorAll(`[data-suppress="${{CSS.escape(id)}}"]`).forEach(button=>button.textContent=isSuppressed?'Expose':'Suppress');document.querySelectorAll(`[data-mobile-report-id="${{CSS.escape(id)}}"]`).forEach(card=>{{card.dataset.acknowledged=isAck?'true':'false';card.dataset.suppressed=isSuppressed?'true':'false'}});const noteText=meta.reason||'';group.querySelectorAll('.suppression-note').forEach(note=>{{note.hidden=!isSuppressed;const text=note.querySelector('.suppression-note-text'),metaEl=note.querySelector('.suppression-note-meta');if(text)text.textContent=noteText||'No reason provided.';if(metaEl)metaEl.textContent=meta.updated_at?`Suppressed ${{meta.updated_at}}`:''}});if(group===selectedGroup)syncPinnedContent(group)}})}}function refreshDynamicCollections(){{groups=[...document.querySelectorAll('.report-row-group')];mobileCards=[...document.querySelectorAll('.mobile-alert-card')]}}
const apiPageStatus=document.querySelector('#api-alert-page-status'),apiPageSize=document.querySelector('#api-page-size'),apiPageSelect=document.querySelector('#api-page-select'),apiPrevPage=document.querySelector('#api-prev-page'),apiNextPage=document.querySelector('#api-next-page');
let apiAlertCursor=null,apiAlertLoading=false,socApiTableEnabled=true,apiAlertReloadTimer=null,socEventsSource=null,socEventsSignature='',socEventsReloadTimer=null,apiCurrentPage=1,apiTotalPages=1,apiTotalMatching=0,apiHighestSeverity='none',apiSeverityCounts=null;
function apiSeverityLevel(alert){{const raw=String(alert.triage_level||alert.severity_label||'informational').toLowerCase();return raw==='info'?'informational':raw}}
function apiSeverityLabel(alert){{const level=apiSeverityLevel(alert);return level==='informational'?'Informational':level.charAt(0).toUpperCase()+level.slice(1)}}
const navSeverityOrder={{critical:5,high:4,medium:3,low:2,informational:1,info:1}};
const navSeverityClasses=['critical','high','medium','low','informational','info','none'];
function normalizeNavSeverity(value){{const level=String(value||'').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');return navSeverityOrder[level]?level:'none'}}
function updateNavAlertSeverity(level){{if(!navVisibleCount)return;const severity=normalizeNavSeverity(level);navVisibleCount.dataset.severity=severity;navSeverityClasses.forEach(name=>navVisibleCount.classList.remove(`nav-count-sev-${{name}}`));navVisibleCount.classList.add(`nav-count-sev-${{severity}}`)}}
function highestSeverityForGroups(groupList){{let highest='none',rank=0;groupList.forEach(group=>{{const level=normalizeNavSeverity(group?.dataset?.criticality),current=navSeverityOrder[level]||0;if(current>rank){{highest=level;rank=current}}}});return highest}}
function apiRiskScore(alert){{const score=Number(alert.triage_score||0);if(score)return score;const rank={{critical:95,high:75,medium:50,low:25,informational:10}};return rank[apiSeverityLevel(alert)]||0}}
function analystStatusParam(){{const ack=Boolean(showAcknowledged?.checked),supp=Boolean(showSuppressed?.checked);if(ack&&!supp)return 'acknowledged';if(supp&&!ack)return 'suppressed';if(!ack&&!supp)return 'open';return ''}}
function apiSinceParam(){{const value=lastSeenWindow?.value||'all';if(value==='all')return '';const minutes=Number(value);return Number.isFinite(minutes)&&minutes>0?`${{minutes}}m`:''}}
function apiPageSizeValue(){{const value=Number(apiPageSize?.value||25);return Number.isFinite(value)&&value>0?value:25}}
function updateSortHeaders(){{sortHeaders.forEach(button=>{{const active=button.dataset.sortKey===apiSortKey;button.dataset.sortActive=active?'true':'false';button.setAttribute('aria-sort',active?(apiSortDirection==='asc'?'ascending':'descending'):'none');const indicator=button.querySelector('.sort-indicator');if(indicator)indicator.textContent=active?(apiSortDirection==='asc'?'▲':'▼'):''}})}}
function defaultSortDirection(key){{return ['alert','source_ip','destination_ip','log_source','ai','enrichment'].includes(key)?'asc':'desc'}}
function applySortingDefault(value,load=true){{const normalized=value==='severity'?'severity':'last_seen';if(sortingDefault)sortingDefault.value=normalized;apiSortKey=normalized;apiSortDirection='desc';try{{localStorage.setItem(sortDefaultStorageKey,normalized)}}catch(_){{}}updateSortHeaders();if(load)loadApiAlerts(true)}}
function initializeSortingDefault(){{let saved='last_seen';try{{saved=localStorage.getItem(sortDefaultStorageKey)||'last_seen'}}catch(_){{}}applySortingDefault(saved,false)}}
function apiBuildUrl(){{const params=new URLSearchParams();params.set('limit',String(apiPageSizeValue()));params.set('page',String(apiCurrentPage));params.set('sort',apiSortKey);params.set('direction',apiSortDirection);const status=analystStatusParam();if(status)params.set('analyst_status',status);const q=(search?.value||'').trim();if(q)params.set('q',q);if(severityFilter&&severityFilter!=='all')params.set('levels',severityFilter);const since=apiSinceParam();if(since)params.set('since',since);return `/api/soc-alerts?${{params.toString()}}`}}
function apiAiPill(alert){{const key=alert.ai_status_key||'not-queued',label=alert.ai_status_label||'Not queued';return `<span class="ai-status-pill ai-status-${{key}}">${{escapeHtml(label)}}</span>`}}
function apiEnrichmentPill(alert){{const key=alert.enrichment_status_key||'none',label=alert.enrichment_status_label||'None',detail=alert.enrichment_status_detail||'No public enrichment data recorded';return `<span class="enrichment-status-pill enrichment-status-${{escapeHtml(key)}}" title="${{escapeHtml(detail)}}">${{escapeHtml(label)}}</span>`}}
function apiPcapPill(alert){{const key=alert.pcap_status_key||'none',label=alert.pcap_status_label||'None',detail=alert.pcap_status_detail||'No parsed PCAP analysis is available';return `<span class="pcap-status-pill pcap-status-${{escapeHtml(key)}}" title="${{escapeHtml(detail)}}">${{escapeHtml(label)}}</span>`}}
function formatApiBytes(value){{const bytes=Number(value||0);if(!Number.isFinite(bytes)||bytes<=0)return '0 B';const units=['B','KB','MB','GB'];let amount=bytes,index=0;while(amount>=1024&&index<units.length-1){{amount/=1024;index+=1}}const digits=index===0?0:amount>=10?1:1;return `${{amount.toFixed(digits).replace(/\\.0$/,'')}} ${{units[index]}}`}}
function apiDetailHtml(alert){{return `<div class="api-detail-grid"><div><b>Representative Alert</b><span>${{escapeHtml(alert.representative_alert_id||'n/a')}}</span></div><div><b>Group Key</b><span>${{escapeHtml(alert.group_key||'n/a')}}</span></div><div><b>First Seen</b><span>${{escapeHtml(alert.first_seen||'n/a')}}</span></div><div><b>Last Seen</b><span>${{escapeHtml(alert.last_seen||'n/a')}}</span></div><div><b>Route</b><span>${{escapeHtml(alert.routing||'n/a')}}</span></div><div><b>Filter Status</b><span>${{escapeHtml(alert.filter_status||'accepted')}}</span></div></div><div class="markdown-body"><h2>API Loaded Alert Summary</h2><ul><li><strong>Rule:</strong> ${{escapeHtml(alert.rule_name||'Security Onion Alert')}}</li><li><strong>Log source:</strong> ${{escapeHtml(alert.event_dataset||'n/a')}}</li><li><strong>Traffic:</strong> ${{escapeHtml(alert.source_ip||'n/a')}}:${{escapeHtml(alert.source_port||'-')}} -> ${{escapeHtml(alert.destination_ip||'n/a')}}:${{escapeHtml(alert.destination_port||'-')}}</li><li><strong>Count:</strong> ${{Number(alert.seen_count||0)}}</li><li><strong>Analyst state:</strong> ${{escapeHtml(alert.analyst_status||'open')}}</li></ul></div>`}}
function parseApiEpoch(value){{const text=String(value||'').replace(/  /,'T');const parsed=Date.parse(text);return Number.isFinite(parsed)?Math.floor(parsed/1000):0}}
function apiRowHtml(alert){{const id=alert.group_id,level=apiSeverityLevel(alert),label=apiSeverityLabel(alert),title=`[${{label.toUpperCase()}}] ${{alert.rule_name||'Security Onion Alert'}}`,lastSeen=alert.last_seen||'',count=Number(alert.seen_count||0),risk=apiRiskScore(alert),src=alert.source_ip||'n/a',dst=alert.destination_ip||'n/a',port=alert.destination_port||'-',source=alert.event_dataset||'n/a',sizeBytes=Number(alert.payload_size_bytes||0)||0,sizeLabel=formatApiBytes(sizeBytes),body=[label,title,source,src,dst,port,alert.group_key,count,sizeLabel,alert.enrichment_status_label||'None',alert.pcap_status_label||'None'].join(' ').toLowerCase(),status=alert.analyst_status||'open',epoch=parseApiEpoch(lastSeen);return `<tbody class="report-row-group" data-report-id="${{escapeHtml(id)}}" data-title="${{escapeHtml(title.toLowerCase())}}" data-source="${{escapeHtml(source.toLowerCase())}}" data-body="${{escapeHtml(body)}}" data-alert-group-key="${{escapeHtml(alert.group_key||'')}}" data-repeat-count="${{count}}" data-criticality="${{escapeHtml(level)}}" data-ai-status="${{escapeHtml(alert.ai_status_key||'not-queued')}}" data-enrichment-status="${{escapeHtml(alert.enrichment_status_key||'none')}}" data-pcap-status="${{escapeHtml(alert.pcap_status_key||'none')}}" data-risk-score="${{risk}}" data-mtime="${{epoch}}" data-alert-ts="${{epoch}}" data-rule-id="" data-rule-name="${{escapeHtml(alert.rule_name||'')}}" data-alert-source="${{escapeHtml(source)}}" data-summary="" data-modified="${{escapeHtml(lastSeen)}}" data-size="${{escapeHtml(sizeLabel)}}" data-size-bytes="${{sizeBytes}}" data-source-ip="${{escapeHtml(src)}}" data-destination-ip="${{escapeHtml(dst)}}" data-destination-port="${{escapeHtml(port)}}" data-source-label="SQLite API" data-acknowledged="${{status==='acknowledged'}}" data-suppressed="${{status==='suppressed'}}"><tr class="report-row" tabindex="0" aria-selected="false"><td class="select-cell"><span class="row-check">✓</span></td><td class="endpoint-cell count-cell"><span class="alert-repeat-count">${{count}}</span></td><td class="severity-cell"><span class="severity-label severity-text-${{escapeHtml(level)}}">${{escapeHtml(label)}}</span></td><td class="last-seen-cell" data-last-seen-utc="${{escapeHtml(lastSeen)}}">${{escapeHtml(lastSeen)}}</td><td class="alert-cell"><strong>${{escapeHtml(title)}}</strong></td><td class="endpoint-cell ip-cell"><code>${{escapeHtml(src)}}</code></td><td class="endpoint-cell ip-cell"><code>${{escapeHtml(dst)}}</code></td><td class="endpoint-cell port-cell"><code>${{escapeHtml(port)}}</code></td><td class="ai-status-cell">${{apiAiPill(alert)}}</td><td class="enrichment-status-cell">${{apiEnrichmentPill(alert)}}</td><td class="pcap-status-cell">${{apiPcapPill(alert)}}</td><td class="source-cell"><code>${{escapeHtml(source)}}</code></td><td>${{escapeHtml(sizeLabel)}}</td><td class="wide-only">${{risk}}</td><td class="action-cell"><button class="ack-button" type="button" data-acknowledge="${{escapeHtml(id)}}">Acknowledge</button><button class="ack-button suppress-button" type="button" data-suppress="${{escapeHtml(id)}}">Suppress</button></td><td class="menu-cell">⋮</td></tr><tr class="detail-template-row"><td colspan="16"><div class="detail-template"><div class="detail-label">Detailed Alert Report</div><div class="suppression-note" hidden><h3>Suppression Note</h3><p class="suppression-note-text"></p><small class="suppression-note-meta"></small></div><div class="api-detail-content" data-detail-loaded="false">${{apiDetailHtml(alert)}}</div></div></td></tr></tbody>`}}
function apiMobileCardHtml(alert){{const id=alert.group_id,level=apiSeverityLevel(alert),label=apiSeverityLabel(alert),title=`[${{label.toUpperCase()}}] ${{alert.rule_name||'Security Onion Alert'}}`;return `<article class="mobile-alert-card" data-mobile-report-id="${{escapeHtml(id)}}" data-acknowledged="${{alert.analyst_status==='acknowledged'}}" data-suppressed="${{alert.analyst_status==='suppressed'}}" data-rule-id="" data-rule-name="${{escapeHtml(alert.rule_name||'')}}"><button class="mobile-alert-pill" type="button" aria-expanded="false" aria-controls="mobile-detail-${{escapeHtml(id)}}"><span class="mobile-card-top"><span class="severity-label severity-text-${{escapeHtml(level)}}">${{escapeHtml(label)}}</span><span class="mobile-card-time">Last Seen <span data-last-seen-utc="${{escapeHtml(alert.last_seen||'')}}">${{escapeHtml(alert.last_seen||'')}}</span></span></span><strong>${{escapeHtml(title)}}</strong><span class="mobile-card-summary">Grouped API alert. Count ${{Number(alert.seen_count||0)}}.</span><span class="mobile-endpoints"><span><b>Src</b><code>${{escapeHtml(alert.source_ip||'n/a')}}:${{escapeHtml(alert.source_port||'-')}}</code></span><span><b>Dst</b><code>${{escapeHtml(alert.destination_ip||'n/a')}}:${{escapeHtml(alert.destination_port||'-')}}</code></span></span><span class="mobile-card-meta"><span>Count <b>${{Number(alert.seen_count||0)}}</b></span><span>Risk <b>${{apiRiskScore(alert)}}</b></span><span>${{apiAiPill(alert)}}</span><span>${{apiEnrichmentPill(alert)}}</span><span>${{apiPcapPill(alert)}}</span><span>API</span></span></button><div id="mobile-detail-${{escapeHtml(id)}}" class="mobile-pill-details" hidden><div class="mobile-card-actions"><button class="ack-button" type="button" data-acknowledge="${{escapeHtml(id)}}">Acknowledge</button><button class="ack-button suppress-button" type="button" data-suppress="${{escapeHtml(id)}}">Suppress</button></div><div class="suppression-note" hidden><h3>Suppression Note</h3><p class="suppression-note-text"></p><small class="suppression-note-meta"></small></div><div class="api-detail-content" data-detail-loaded="false">${{apiDetailHtml(alert)}}</div></div></article>`}}
function ensureApiTableMetricFooter(){{const metrics=document.querySelector('.api-pagination .api-table-metrics');if(!metrics)return null;if(!metrics.querySelector('#api-grouped-total')){{metrics.insertAdjacentHTML('afterbegin','<span class="api-table-metric total"><b id="api-grouped-total">0</b> Total</span>')}}if(!document.querySelector('#api-table-metric-style')){{const style=document.createElement('style');style.id='api-table-metric-style';style.textContent='.api-table-metrics{{display:inline-flex;align-items:center;gap:8px;flex-wrap:wrap;margin-left:auto}}.api-table-metric{{display:inline-flex;align-items:center;gap:6px;border:1px solid rgba(34,211,238,.18);border-radius:999px;padding:4px 10px;color:#9fb0c4;background:rgba(34,211,238,.045);font-size:12px;font-weight:850;white-space:nowrap}}.api-table-metric b{{color:#8ff4ff;font-size:16px;font-variant-numeric:tabular-nums}}.api-table-metric.total{{border-color:rgba(148,163,184,.22);background:rgba(148,163,184,.05)}}.api-table-metric.total b{{color:#eef8ff}}.api-table-metric.suppressed{{border-color:rgba(251,113,133,.30);background:rgba(251,113,133,.06)}}.api-table-metric.suppressed b{{color:#fb7185}}.api-table-metric.acknowledged{{border-color:rgba(246,199,109,.30);background:rgba(246,199,109,.06)}}.api-table-metric.acknowledged b{{color:#f6c76d}}.api-table-metric.network{{border-color:rgba(34,211,238,.18);background:rgba(34,211,238,.04)}}.api-table-metric.network span{{color:#9fb0c4}}.api-table-metric.network b{{color:#e8f1fb;font-size:14px;max-width:170px;overflow:hidden;text-overflow:ellipsis}}.severity-summary-card{{align-items:center;gap:12px;overflow:hidden;padding:14px 14px}}.severity-summary-main{{min-width:0;flex:1 1 auto}}.severity-summary-main strong{{font-size:15px;line-height:1.1;white-space:nowrap}}.severity-card-counts{{display:grid;grid-template-columns:repeat(2,max-content);gap:7px 13px;margin-top:9px;align-items:center}}.severity-card-counts .sev-chip{{font-size:11px;gap:5px;line-height:1;white-space:nowrap}}px;line-height:1}}.severity-card-counts .sev-zero b{{color:var(--cyan)!important}}.alert-status-card{{align-items:stretch;gap:0;overflow:hidden;padding:13px 14px}}.alert-status-card .metric-icon{{display:none}}.alert-status-main{{min-width:0;flex:1 1 auto}}.alert-status-main strong{{font-size:18px;line-height:1.1;letter-spacing:-.02em;white-space:nowrap}}.alert-status-metrics{{display:grid;grid-template-columns:70px minmax(0,1fr);justify-content:start;align-items:baseline;gap:9px 18px;margin:12px 0 0}}.alert-status-metrics .api-table-metric{{display:inline-flex;align-items:baseline;gap:5px;min-width:0;width:auto;justify-content:flex-start;border:0;border-radius:0;padding:0;color:#9fb0c4;background:transparent;box-shadow:none;font-size:12px;font-weight:500;line-height:1;white-space:nowrap}}px;font-weight:850;line-height:1;letter-spacing:0}}.health[data-health-state="unknown"] .status-dot{{background:#94a3b8}}.health[data-health-state="ok"] .status-dot{{background:var(--green);box-shadow:0 0 10px rgba(34,197,94,.40)}}.health[data-health-state="stale"]{{border-color:rgba(251,113,133,.28);background:rgba(251,113,133,.045)}}.health[data-health-state="stale"] .status-dot{{background:var(--red);box-shadow:0 0 10px rgba(251,113,133,.42)}}.health[data-health-state="stale"] span{{color:#ffd6de}}.alert-rollup-strip{{display:flex;align-items:center;justify-content:flex-start;margin:-2px 0 14px;padding:0}}.alert-rollup-metrics{{margin-left:0;gap:10px}}.alert-rollup-metrics .api-table-metric{{padding:7px 14px;font-size:15px}}.alert-rollup-metrics .api-table-metric b{{font-size:22px;line-height:1}}.alert-rollup-metrics .api-table-metric.network{{font-size:12px;padding:7px 12px}}.alert-rollup-metrics .api-table-metric.network b{{font-size:14px;line-height:1.1;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace}}@media(max-width:640px){{.alert-status-card{{align-items:flex-start}}.alert-status-metrics{{grid-template-columns:70px minmax(0,1fr);gap:9px 18px}}.alert-status-metrics .api-table-metric{{padding:0;font-size:12px}}.alert-rollup-strip{{margin:0 0 12px}}.alert-rollup-metrics{{gap:7px}}.alert-rollup-metrics .api-table-metric{{padding:6px 10px;font-size:13px}}.alert-rollup-metrics .api-table-metric b{{font-size:18px}}}}';document.head.appendChild(style)}}return metrics}}function updateApiTableMetrics(data){{ensureApiTableMetricFooter();const counts=data?.status_counts||{{}},visible=Number(counts.open??counts.active??data?.total_matching??0)||0,suppressed=Number(counts.suppressed||0)||0,acknowledged=Number(counts.acknowledged||0)||0,total=Number(counts.total??(visible+suppressed+acknowledged))||0;const set=(selector,value)=>{{document.querySelectorAll(selector).forEach(el=>el.textContent=String(value))}};set('#api-grouped-total,#top-api-grouped-total',total);setActiveAlertCount(visible);set('#api-suppressed-total,#top-api-suppressed-total',suppressed);set('#api-acknowledged-total,#top-api-acknowledged-total',acknowledged);const endpoints=data?.top_endpoints||{{}};set('#top-api-source-ip',endpoints.source_ip||'n/a');set('#top-api-destination-ip',endpoints.destination_ip||'n/a');set('#top-api-destination-port',endpoints.destination_port||'n/a')}}function renderApiPagination(data){{updateApiTableMetrics(data);apiCurrentPage=Number(data.page||apiCurrentPage)||1;apiTotalPages=Math.max(1,Number(data.total_pages||1)||1);apiTotalMatching=Number(data.total_matching||0)||0;apiHighestSeverity=normalizeNavSeverity(data.highest_severity||'none');apiSeverityCounts=data.severity_counts||null;if(navVisibleCount&&appShell?.dataset.view==='alerts'){{setActiveAlertCount(apiTotalMatching);updateNavAlertSeverity(apiHighestSeverity||highestSeverityForGroups([...document.querySelectorAll('tbody.report-row-group')].filter(group=>getComputedStyle(group).display!=='none')))}}if(data.sort)apiSortKey=String(data.sort);if(data.direction)apiSortDirection=String(data.direction)==='asc'?'asc':'desc';updateSortHeaders();if(apiPageSelect){{apiPageSelect.innerHTML='';for(let page=1;page<=apiTotalPages;page+=1){{apiPageSelect.add(new Option(`Page ${{page}} of ${{apiTotalPages}}`,String(page),false,page===apiCurrentPage))}}apiPageSelect.disabled=apiTotalPages<=1}}if(apiPrevPage)apiPrevPage.disabled=apiCurrentPage<=1;if(apiNextPage)apiNextPage.disabled=apiCurrentPage>=apiTotalPages;if(apiPageStatus){{const start=apiTotalMatching?((apiCurrentPage-1)*apiPageSizeValue())+1:0,end=Math.min(apiCurrentPage*apiPageSizeValue(),apiTotalMatching);apiPageStatus.textContent=`Showing ${{start}}-${{end}} of ${{apiTotalMatching}} grouped detections`}}}}
function renderApiAlerts(data,reset=true){{const table=document.querySelector('.alert-table'),mobileList=document.querySelector('.mobile-alert-list');if(!table||!data||!Array.isArray(data.alerts))return;const rows=data.alerts.map(apiRowHtml).join('');table.querySelectorAll('tbody.report-row-group').forEach(row=>row.remove());table.insertAdjacentHTML('beforeend',rows);if(mobileList){{mobileList.innerHTML='';mobileList.insertAdjacentHTML('beforeend',data.alerts.map(apiMobileCardHtml).join(''))}}apiAlertCursor=data.next_cursor||null;renderApiPagination(data);refreshDynamicCollections();bindGroupInteractions();hydrateTriageStatuses();renderLocalLastSeen();updateDetailViewport();applyFilter();pollSocAlertStatus()}}
async function loadApiAlerts(reset=true){{const table=document.querySelector('.alert-table');if(!table||apiAlertLoading)return;if(reset)apiCurrentPage=1;apiAlertLoading=true;socApiTableEnabled=true;if(apiPageStatus)apiPageStatus.textContent='Loading alerts from SQLite API...';try{{const response=await fetch(apiBuildUrl(),{{cache:'no-store'}});if(!response.ok)throw new Error(`HTTP ${{response.status}}`);const data=await response.json();renderApiAlerts(data,reset)}}catch(error){{socApiTableEnabled=false;if(apiPageStatus)apiPageStatus.textContent=`API table unavailable; using static fallback (${{error.message}})`}}finally{{apiAlertLoading=false}}}}
function scheduleApiReload(){{if(!socApiTableEnabled)return;clearTimeout(apiAlertReloadTimer);apiAlertReloadTimer=setTimeout(()=>loadApiAlerts(true),180)}}
function applyFilter(){{const q=(search?.value||'').trim().toLowerCase(),includeAcknowledged=Boolean(showAcknowledged?.checked),includeSuppressed=Boolean(showSuppressed?.checked),lastSeenWindowValue=lastSeenWindow?.value||'all',lastSeenMinutes=lastSeenWindowValue==='all'?0:Number(lastSeenWindowValue),lastSeenCutoff=lastSeenMinutes?Math.floor(Date.now()/1000)-(lastSeenMinutes*60):0;let visible=0;const visibleGroups=[];groups.forEach(group=>{{const haystack=[group.dataset.title,group.dataset.source,group.dataset.body,group.dataset.criticality,group.dataset.ruleId,group.dataset.ruleName].join(' ').toLowerCase(),matchesSearch=!q||haystack.includes(q),matchesSeverity=severityFilter==='all'||group.dataset.criticality===severityFilter,status=statusForGroup(group).status,isAck=status==='acknowledged',isSuppressed=status==='suppressed',lastSeenEpoch=Number(group.dataset.mtime||0),matchesLastSeen=!lastSeenCutoff||(lastSeenEpoch>=lastSeenCutoff),show=matchesSearch&&matchesSeverity&&matchesLastSeen&&(includeAcknowledged||!isAck)&&(includeSuppressed||!isSuppressed);group.style.display=show?'':'none';document.querySelectorAll(`[data-mobile-report-id="${{CSS.escape(group.dataset.reportId)}}"]`).forEach(card=>card.style.display=show?'':'none');if(!show)collapseGroup(group);if(show){{visible+=1;visibleGroups.push(group)}}}});if(visibleCount)visibleCount.textContent=String(socApiTableEnabled?apiTotalMatching:visible);if(navVisibleCount&&groups.length&&appShell?.dataset.view==='alerts'){{if(socApiTableEnabled){{setActiveAlertCount(apiTotalMatching);updateNavAlertSeverity(apiHighestSeverity||highestSeverityForGroups(visibleGroups))}}else{{setActiveAlertCount(visible);updateNavAlertSeverity(highestSeverityForGroups(visibleGroups))}}}}const visibleExtra=document.querySelector('#visible-metric-extra');if(visibleExtra)visibleExtra.innerHTML=(socApiTableEnabled&&apiSeverityCounts)?buildSeverityBreakdownFromCounts(apiSeverityCounts):buildSeverityBreakdown(visibleGroups);if(selectedGroup&&getComputedStyle(selectedGroup).display==='none')selectedGroup=null;sortMobileCards();updatePinnedRow()}}function updateSuppressionDialogState(){{const length=(suppressReasonInput?.value||'').length;if(suppressCharCount)suppressCharCount.textContent=`${{length}} / 140`;if(confirmSuppressionButton)confirmSuppressionButton.disabled=(suppressReasonInput?.value||'').trim().length===0}}function syncSuppressionVisualViewport(){{if(!suppressModal)return;const viewport=window.visualViewport;if(viewport){{suppressModal.style.setProperty('--suppress-vv-height',`${{viewport.height}}px`);suppressModal.style.setProperty('--suppress-vv-offset-top',`${{viewport.offsetTop}}px`)}}else{{suppressModal.style.removeProperty('--suppress-vv-height');suppressModal.style.removeProperty('--suppress-vv-offset-top')}}}}function centerSuppressionReasonInput(){{syncSuppressionVisualViewport();window.requestAnimationFrame(()=>suppressReasonInput?.scrollIntoView({{block:'center',inline:'nearest'}}))}}function cleanNetworkPart(value){{const text=String(value||'').trim();return text&&!['n/a','na','unknown','unknown-source','unknown-destination','-','none','null','undefined'].includes(text.toLowerCase())?text:''}}function networkContextForGroup(group){{if(!group)return '';const ipCells=[...group.querySelectorAll('.ip-cell code')],portCell=group.querySelector('.port-cell code'),src=cleanNetworkPart(group.dataset.sourceIp)||cleanNetworkPart(ipCells[0]?.textContent),dst=cleanNetworkPart(group.dataset.destinationIp)||cleanNetworkPart(ipCells[1]?.textContent),port=cleanNetworkPart(group.dataset.destinationPort)||cleanNetworkPart(portCell?.textContent);if(!src||!dst)return '';return port?`${{src}} > ${{dst}} : ${{port}}`:`${{src}} > ${{dst}}`}}function setSuppressionNetworkContext(group){{if(!suppressNetworkContext)return;const context=networkContextForGroup(group);suppressNetworkContext.textContent=context;suppressNetworkContext.hidden=!context}}function openSuppressionDialog(group){{pendingSuppressGroup=group;if(!suppressModal||!suppressReasonInput)return;const title=group?.querySelector('.alert-cell strong')?.textContent||'this alert';suppressReasonInput.value='';suppressReasonInput.setAttribute('placeholder',`Reason for suppressing ${{title}}`);setSuppressionNetworkContext(group);syncSuppressionVisualViewport();suppressModal.hidden=false;updateSuppressionDialogState();setTimeout(()=>{{suppressReasonInput.focus();centerSuppressionReasonInput()}},30)}}function closeSuppressionDialog(){{if(suppressModal)suppressModal.hidden=true;pendingSuppressGroup=null;if(suppressReasonInput)suppressReasonInput.value='';if(suppressNetworkContext){{suppressNetworkContext.textContent='';suppressNetworkContext.hidden=true}}updateSuppressionDialogState()}}suppressReasonInput?.addEventListener('input',updateSuppressionDialogState);suppressReasonInput?.addEventListener('focus',centerSuppressionReasonInput);window.visualViewport?.addEventListener('resize',()=>{{if(!suppressModal?.hidden)centerSuppressionReasonInput()}});window.visualViewport?.addEventListener('scroll',()=>{{if(!suppressModal?.hidden)syncSuppressionVisualViewport()}});cancelSuppressionButton?.addEventListener('click',closeSuppressionDialog);suppressModal?.addEventListener('click',event=>{{if(event.target===suppressModal)closeSuppressionDialog()}});document.addEventListener('keydown',event=>{{if(event.key==='Escape'&&!suppressModal?.hidden)closeSuppressionDialog()}});confirmSuppressionButton?.addEventListener('click',()=>{{const reason=(suppressReasonInput?.value||'').trim().slice(0,140);if(!pendingSuppressGroup||!reason)return;const group=pendingSuppressGroup;closeSuppressionDialog();setTriageStatus(group,'suppressed',reason)}});function bindGroupInteractions(){{groups.forEach(group=>{{if(group.dataset.bound==='true')return;group.dataset.bound='true';const row=group.querySelector('.report-row');row?.addEventListener('click',event=>{{if(event.target.closest('button'))return;toggleGroup(group)}});row?.addEventListener('keydown',event=>{{if(event.key==='Enter'||event.key===' '){{event.preventDefault();toggleGroup(group)}}}});group.querySelectorAll('[data-acknowledge]').forEach(button=>button.addEventListener('click',event=>{{event.preventDefault();event.stopPropagation();const next=statusForGroup(group).status==='acknowledged'?'open':'acknowledged';setTriageStatus(group,next)}}));group.querySelectorAll('[data-suppress]').forEach(button=>button.addEventListener('click',event=>{{event.preventDefault();event.stopPropagation();if(statusForGroup(group).status==='suppressed')setTriageStatus(group,'open');else openSuppressionDialog(group)}}))}})}}bindGroupInteractions();severityFilterButtons.forEach(button=>button.addEventListener('click',()=>{{severityFilter=button.dataset.severityFilter||'all';severityFilterButtons.forEach(b=>b.classList.toggle('active',b===button));applyFilter();loadApiAlerts(true)}}));viewButtons.forEach(button=>button.addEventListener('click',event=>{{event.preventDefault();setView(button.dataset.viewTarget||'overview')}}));mobileSort?.addEventListener('change',sortMobileCards);function toggleMobileCard(card,group){{if(!card||!group)return;const pill=card.querySelector('.mobile-alert-pill'),detail=card.querySelector('.mobile-pill-details'),expanded=card.classList.toggle('mobile-expanded');if(pill)pill.setAttribute('aria-expanded',String(expanded));if(detail)detail.hidden=!expanded;if(expanded)loadGroupDetail(group)}}document.querySelector('.mobile-alert-list')?.addEventListener('click',event=>{{const ackButton=event.target.closest('[data-acknowledge]'),suppressButton=event.target.closest('[data-suppress]'),button=ackButton||suppressButton;if(button){{const id=button.dataset.acknowledge||button.dataset.suppress,group=groups.find(g=>g.dataset.reportId===id);if(!group)return;event.preventDefault();event.stopPropagation();if(ackButton){{const next=statusForGroup(group).status==='acknowledged'?'open':'acknowledged';setTriageStatus(group,next)}}else{{if(statusForGroup(group).status==='suppressed')setTriageStatus(group,'open');else openSuppressionDialog(group)}}return}}const pill=event.target.closest('.mobile-alert-pill');if(!pill)return;const card=pill.closest('.mobile-alert-card'),id=card?.dataset.mobileReportId,group=groups.find(g=>g.dataset.reportId===id);if(!card||!group)return;event.preventDefault();toggleMobileCard(card,group)}});pinnedRow?.addEventListener('click',event=>{{if(!selectedGroup)return;const ackButton=event.target.closest('[data-acknowledge]'),suppressButton=event.target.closest('[data-suppress]');event.preventDefault();event.stopPropagation();if(ackButton){{const next=statusForGroup(selectedGroup).status==='acknowledged'?'open':'acknowledged';setTriageStatus(selectedGroup,next);return}}if(suppressButton){{if(statusForGroup(selectedGroup).status==='suppressed')setTriageStatus(selectedGroup,'open');else openSuppressionDialog(selectedGroup);return}}toggleGroup(selectedGroup)}});function refreshAlertsTable(){{if(socApiTableEnabled){{loadApiAlerts(true);return}}if(socRefreshButton){{socRefreshButton.classList.add('refreshing');socRefreshButton.setAttribute('aria-busy','true');socRefreshButton.setAttribute('aria-label','Refreshing SOC Alerts table');socRefreshButton.setAttribute('title','Refreshing SOC Alerts table');socRefreshButton.disabled=true}}const url=new URL(window.location.href);url.searchParams.set('alerts_refresh',Date.now().toString());window.requestAnimationFrame(()=>window.setTimeout(()=>window.location.replace(url.toString()),90))}}socRefreshButton?.addEventListener('click',refreshAlertsTable);search?.addEventListener('input',applyFilter);search?.addEventListener('input',scheduleApiReload);showAcknowledged?.addEventListener('change',applyFilter);showAcknowledged?.addEventListener('change',()=>loadApiAlerts(true));showSuppressed?.addEventListener('change',applyFilter);showSuppressed?.addEventListener('change',()=>loadApiAlerts(true));lastSeenWindow?.addEventListener('change',applyFilter);lastSeenWindow?.addEventListener('change',()=>loadApiAlerts(true));sortingDefault?.addEventListener('change',()=>applySortingDefault(sortingDefault.value,true));apiPageSize?.addEventListener('change',()=>loadApiAlerts(true));sortHeaders.forEach(button=>button.addEventListener('click',()=>{{const key=button.dataset.sortKey||'last_seen';if(apiSortKey===key)apiSortDirection=apiSortDirection==='asc'?'desc':'asc';else{{apiSortKey=key;apiSortDirection=defaultSortDirection(key)}}updateSortHeaders();loadApiAlerts(true)}}));apiPageSelect?.addEventListener('change',()=>{{apiCurrentPage=Number(apiPageSelect.value||1)||1;loadApiAlerts(false)}});apiPrevPage?.addEventListener('click',()=>{{if(apiCurrentPage>1){{apiCurrentPage-=1;loadApiAlerts(false)}}}});apiNextPage?.addEventListener('click',()=>{{if(apiCurrentPage<apiTotalPages){{apiCurrentPage+=1;loadApiAlerts(false)}}}});function setMobileMenuOpen(open){{appShell?.classList.toggle('mobile-menu-open',open);if(mobileControlsToggle){{mobileControlsToggle.setAttribute('aria-expanded',String(open));mobileControlsToggle.setAttribute('aria-label',open?'Close alert controls':'Open alert controls');mobileControlsToggle.setAttribute('title',open?'Close alert controls':'Alert controls')}}stickyTop();updatePinnedRow()}}mobileControlsToggle?.addEventListener('click',()=>setMobileMenuOpen(!appShell?.classList.contains('mobile-menu-open')));sidebarToggle?.addEventListener('click',()=>setSidebarCollapsed(!appShell?.classList.contains('sidebar-collapsed')));tableCard?.addEventListener('scroll',()=>{{updateDetailViewport();updatePinnedRow()}},{{passive:true}});window.addEventListener('resize',()=>{{updateDetailViewport();updatePinnedRow()}});window.addEventListener('scroll',updatePinnedRow,{{passive:true}});renderLocalLastSeen();stickyTop();setView(appShell?.dataset.view||'overview');try{{const savedSidebarState=localStorage.getItem(sidebarStorageKey),mobileSidebarDefault=window.matchMedia('(max-width: 760px)').matches;setSidebarCollapsed(mobileSidebarDefault||savedSidebarState===null?true:savedSidebarState==='1')}}catch(_){{setSidebarCollapsed(true)}}setVerboseMode(false);initializeSortingDefault();hydrateTriageStatuses();applyFilter();const socEventsStarted=connectSocAlertEvents();loadServerStatuses();loadApiAlerts(true);pollSocAlertStatus();pollN8nBeacon();pollSocAlertMetrics();setInterval(loadServerStatuses,socEventsStarted?30000:5000);setInterval(pollSocAlertStatus,socEventsStarted?30000:5000);setInterval(pollN8nBeacon,socEventsStarted?30000:3000);setInterval(pollSocAlertMetrics,socEventsStarted?30000:5000);
}})();
</script><script>
(() => {{
  const pageSizeFor = section => {{
    const value = Number(section?.dataset?.timelinePageSize || section?.querySelector('.alert-timeline-pagination')?.dataset?.timelinePageSize || 25);
    return Number.isFinite(value) && value > 0 ? value : 25;
  }};
  function renderTimelinePage(section) {{
    const rows = [...section.querySelectorAll('tr[data-timeline-row]')];
    if (!rows.length) return;
    const pageSize = pageSizeFor(section);
    const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
    const pagination = section.querySelector('.alert-timeline-pagination');
    let page = Number(section.dataset.timelinePage || 1);
    page = Math.max(1, Math.min(totalPages, Number.isFinite(page) ? page : 1));
    section.dataset.timelinePage = String(page);
    const startIndex = (page - 1) * pageSize;
    const endIndex = Math.min(rows.length, startIndex + pageSize);
    rows.forEach((row, index) => {{
      row.hidden = index < startIndex || index >= endIndex;
    }});
    if (!pagination) return;
    pagination.hidden = totalPages <= 1;
    const prev = pagination.querySelector('[data-timeline-prev]');
    const next = pagination.querySelector('[data-timeline-next]');
    const label = pagination.querySelector('[data-timeline-page-label]');
    if (prev) prev.disabled = page <= 1;
    if (next) next.disabled = page >= totalPages;
    if (label) label.textContent = `Page ${{page}} of ${{totalPages}} · Showing ${{startIndex + 1}}-${{endIndex}} of ${{rows.length}}`;
  }}
  function hydrateTimelinePagination(root = document) {{
    root.querySelectorAll?.('.alert-timeline-section').forEach(section => {{
      if (section.dataset.timelinePaginationBound !== 'true') {{
        section.dataset.timelinePaginationBound = 'true';
        section.querySelector('[data-timeline-prev]')?.addEventListener('click', () => {{
          section.dataset.timelinePage = String(Math.max(1, Number(section.dataset.timelinePage || 1) - 1));
          renderTimelinePage(section);
        }});
        section.querySelector('[data-timeline-next]')?.addEventListener('click', () => {{
          section.dataset.timelinePage = String(Number(section.dataset.timelinePage || 1) + 1);
          renderTimelinePage(section);
        }});
      }}
      renderTimelinePage(section);
    }});
  }}
  hydrateTimelinePagination();
  new MutationObserver(mutations => {{
    mutations.forEach(mutation => {{
      mutation.addedNodes.forEach(node => {{
        if (node.nodeType === 1) hydrateTimelinePagination(node);
      }});
    }});
  }}).observe(document.body, {{ childList: true, subtree: true }});
}})();
</script></body></html>'''


NAV_ICONS = {
    'home': '<svg viewBox="0 0 24 24"><path d="M3.5 11.5 12 4l8.5 7.5"/><path d="M6 10.5V20h12v-9.5"/><path d="M10 20v-5h4v5"/></svg>',
    'system_health': '<svg viewBox="0 0 24 24"><path d="M3 12h4l2-5 4 10 2-5h6"/><circle cx="19" cy="12" r="1.6"/></svg>',
    'flow': '<svg viewBox="0 0 24 24"><path d="M3 7.5c1.7 1.4 3.4 1.4 5.1 0s3.4-1.4 5.1 0 3.4 1.4 5.1 0c.9-.7 1.8-1.1 2.7-1.1"/><path d="M3 12.5c1.7 1.4 3.4 1.4 5.1 0s3.4-1.4 5.1 0 3.4 1.4 5.1 0c.9-.7 1.8-1.1 2.7-1.1"/><path d="M3 17.5c1.7 1.4 3.4 1.4 5.1 0s3.4-1.4 5.1 0 3.4 1.4 5.1 0c.9-.7 1.8-1.1 2.7-1.1"/></svg>',
    'alerts': '<svg viewBox="0 0 24 24"><circle cx="6" cy="7" r="1.6"/><circle cx="6" cy="12" r="1.6"/><circle cx="6" cy="17" r="1.6"/><path d="M10 7h10M10 12h10M10 17h10"/></svg>',
    'threat_hunter': '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="6.5"/><circle cx="12" cy="12" r="2.4"/><path d="M12 3.5v3M12 17.5v3M3.5 12h3M17.5 12h3"/></svg>',
    'cyber_threat_intel': '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="7"/><path d="M12 5v14M5 12h14"/><path d="M7.5 7.5c2.6 1.4 6.4 1.4 9 0M7.5 16.5c2.6-1.4 6.4-1.4 9 0"/></svg>',
    'investigations': '<svg viewBox="0 0 24 24"><path d="M8 5H6.5A2.5 2.5 0 0 0 4 7.5v11A2.5 2.5 0 0 0 6.5 21h11a2.5 2.5 0 0 0 2.5-2.5v-11A2.5 2.5 0 0 0 17.5 5H16"/><path d="M9 3h6v4H9z"/><path d="M8 12h8M8 16h6"/></svg>',
    'reports': '<svg viewBox="0 0 24 24"><circle cx="12" cy="5" r="3"/><circle cx="5" cy="19" r="3"/><circle cx="19" cy="19" r="3"/><path d="M10.5 7.6 6.5 16.4M13.5 7.6l4 8.8M8 19h8"/></svg>',
    'playbooks': '<svg viewBox="0 0 24 24"><path d="M4 20V11h4v9M10 20V5h4v15M16 20V8h4v12M3 20h18"/></svg>',
    'automations': '<svg viewBox="0 0 24 24"><path d="M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7Z"/><path d="M19.4 15a8 8 0 0 0 .1-1l2-1.5-2-3.5-2.4 1a7.8 7.8 0 0 0-1.7-1L15 6.5h-4L10.6 9a7.8 7.8 0 0 0-1.7 1l-2.4-1-2 3.5 2 1.5a8 8 0 0 0 .1 2l-2 1.5 2 3.5 2.4-1a7.8 7.8 0 0 0 1.7 1l.4 2.5h4l.4-2.5a7.8 7.8 0 0 0 1.7-1l2.4 1 2-3.5-2.2-1.5Z"/></svg>',
    'sources': '<svg viewBox="0 0 24 24"><ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6"/><path d="M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"/></svg>',
    'siem_engineering': '<svg viewBox="0 0 24 24"><path d="M4 6h7M15 6h5M4 12h4M12 12h8M4 18h10M18 18h2"/><circle cx="13" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="16" cy="18" r="2"/></svg>',
    'settings': '<svg viewBox="0 0 24 24"><path d="M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7Z"/><path d="M19.4 15a8 8 0 0 0 .1-1l2-1.5-2-3.5-2.4 1a7.8 7.8 0 0 0-1.7-1L15 6.5h-4L10.6 9a7.8 7.8 0 0 0-1.7 1l-2.4-1-2 3.5 2 1.5a8 8 0 0 0 .1 2l-2 1.5 2 3.5 2.4-1a7.8 7.8 0 0 0 1.7 1l.4 2.5h4l.4-2.5a7.8 7.8 0 0 0 1.7-1l2.4 1 2-3.5-2.2-1.5Z"/></svg>',
}


def build_nav_html(active_page: str, report_count: int, severity_class: str = 'none') -> str:
    links = []
    safe_severity = criticality_class(severity_class)
    for key, filename, title, _subtitle in PAGE_DEFS:
        active_class = ' active' if key == active_page else ''
        count = f'<span class="nav-count nav-count-sev-{html.escape(safe_severity)}" id="soc-alerts-nav-count" data-severity="{html.escape(safe_severity)}">{report_count}</span>' if key == 'alerts' else ''
        icon = NAV_ICONS[key]
        links.append(
            f'<a class="nav-item{active_class}" href="{filename}" title="{html.escape(title)}" aria-label="{html.escape(title)}">'
            f'<span class="nav-left"><span class="nav-icon" aria-hidden="true">{icon}</span>'
            f'<span class="nav-label">{html.escape(title)}</span></span>{count}</a>'
        )
    return '<nav class="nav">' + ''.join(links) + '</nav>'


def placeholder_page_section(page_key: str) -> str:
    page = PAGE_BY_KEY[page_key]
    title = html.escape(page['title'])
    subtitle = html.escape(page['subtitle'])
    return f'''
    <section class="view-section active placeholder-view" aria-label="{title}">
      <div class="empty">
        <h2>{title}</h2>
        <p>{subtitle}</p>
        <p>This page now has its own route. Data-backed widgets can be added here without changing the SOC Alerts table page.</p>
      </div>
    </section>'''


def siem_engineering_tuning_row(report: AlertReport) -> str:
    action = report.recommended_tuning_actions[0] if report.recommended_tuning_actions else 'Review this detection after the SIEM Engineer model run completes.'
    route = f'{report.source_ip} > {report.destination_ip} : {report.destination_port}'
    return f'''
    <tr>
      <td><span class="severity-label severity-text-{html.escape(criticality_class(report.criticality))}">{html.escape(report.criticality)}</span></td>
      <td><strong>{html.escape(report.rule_name or report.title)}</strong><code>{html.escape(route)}</code></td>
      <td><span class="siem-table-pill">{html.escape(report.tuning_recommendation or 'review')}</span></td>
      <td class="siem-reason-cell"><p>{html.escape(compact_text(report.tuning_reason or ai_summary_for(report), 135))}</p><em>{html.escape(compact_text(action, 135))}</em></td>
      <td><b>{report.repeat_count}</b><span>{html.escape(report.ai_status_label)}</span></td>
    </tr>'''


def siem_engineering_detection_row(report: AlertReport) -> str:
    destination = f'{report.destination_ip}:{report.destination_port}'
    return f'''
    <tr>
      <td><span class="severity-label severity-text-{html.escape(criticality_class(report.criticality))}">{html.escape(report.criticality)}</span></td>
      <td><strong>{html.escape(report.rule_name or report.title)}</strong><code>{html.escape(report.alert_source)}</code></td>
      <td><span class="siem-table-pill">candidate</span></td>
      <td class="siem-reason-cell"><p>{html.escape(compact_text(ai_summary_for(report), 135))}</p><em>Repeated target: {html.escape(destination)}</em></td>
      <td><b>{report.repeat_count}</b><span>{html.escape(last_seen_iso_for(report))}</span></td>
    </tr>'''


def siem_engineering_roi_score(report: AlertReport) -> tuple[int, int, int, float]:
    has_model_tuning = 1 if report.tuning_recommendation and report.tuning_recommendation not in {'none', 'n/a', 'needs_more_data'} else 0
    repeat_weight = max(report.repeat_count, report.raw_alert_count, report.total_seen_count, 1)
    return (
        has_model_tuning,
        repeat_weight * max(report.criticality_rank, 1),
        repeat_weight,
        report.alert_ts,
    )


def siem_engineering_best_roi_section(reports: list[AlertReport]) -> str:
    candidates = [
        report for report in reports
        if report.tuning_recommendation and report.tuning_recommendation not in {'none', 'n/a'}
    ]
    if not candidates:
        candidates = [report for report in reports if report.repeat_count >= 2]
    if not candidates:
        return '''
      <section class="siem-roi-card" aria-label="Best ROI tuning candidate">
        <div class="siem-roi-head">
          <span class="settings-kicker">#1 ROI tune</span>
          <h3>No candidate yet</h3>
        </div>
        <table class="siem-roi-table"><tbody><tr><th>Why</th><td>No repeated or model-backed candidate.</td></tr><tr><th>Tune</th><td>Wait for analysis, then tune only scoped rule/source/destination/port evidence.</td></tr><tr><th>Activity</th><td>0 observations</td></tr></tbody></table>
      </section>'''

    best = max(candidates, key=siem_engineering_roi_score)
    action = best.recommended_tuning_actions[0] if best.recommended_tuning_actions else (
        'Run SIEM Engineer review before changing rules; tune only with a scoped condition such as rule name, source, destination, destination port, direction, or time window.'
    )
    route = f'{best.source_ip} > {best.destination_ip} : {best.destination_port}'
    observation_count = max(best.repeat_count, best.raw_alert_count, best.total_seen_count, 1)
    if best.tuning_recommendation in {'none', 'n/a', 'needs_more_data'}:
        tuning_type = 'review'
        why = (
            f'This is the highest ROI review candidate because it has {observation_count} observations '
            f'and {best.criticality} severity, but the model has not provided a safe tuning action yet.'
        )
    else:
        tuning_type = best.tuning_recommendation
        why = best.tuning_reason or (
            f'This is the highest ROI tuning candidate because it combines {observation_count} observations, '
            f'{best.criticality} severity, and a model-backed {best.tuning_recommendation} recommendation.'
        )
    return f'''
      <section class="siem-roi-card" aria-label="Best ROI tuning candidate">
        <div class="siem-roi-head">
          <div>
            <span class="settings-kicker">#1 ROI tune</span>
            <h3>{html.escape(best.rule_name or best.title)}</h3>
            <code>{html.escape(route)}</code>
          </div>
          <div class="siem-roi-rank">
            <span>#1 ROI</span>
            <strong class="severity-text-{html.escape(criticality_class(best.criticality))}">{html.escape(best.criticality)}</strong>
          </div>
        </div>
        <table class="siem-roi-table"><tbody>
          <tr><th>Why</th><td>{html.escape(compact_text(why, 180))}</td></tr>
          <tr><th>Tune</th><td>{html.escape(compact_text(action, 180))}</td></tr>
          <tr><th>Activity</th><td>{html.escape(str(observation_count))} observations · {html.escape(tuning_type)} · {html.escape(best.ai_status_label)}</td></tr>
        </tbody></table>
      </section>'''


def siem_engineering_table(title: str, subtitle: str, rows: str, empty: str) -> str:
    body = rows or f'<tr class="siem-empty-row"><td colspan="5">{html.escape(empty)}</td></tr>'
    return f'''
    <section class="siem-table-section" aria-label="{html.escape(title)}">
      <div class="siem-table-title"><h3>{html.escape(title)}</h3></div>
      <div class="siem-table-wrap">
        <table class="siem-engineering-table">
          <thead><tr><th>Severity</th><th>Detection</th><th>Type</th><th>Why / tune</th><th>Seen</th></tr></thead>
          <tbody>{body}</tbody>
        </table>
      </div>
    </section>'''


def siem_engineering_page_section(reports: list[AlertReport]) -> str:
    settings = load_soc_ai_settings()
    mode = settings.get('mode', 'ollama')
    local_model = settings.get('ollama_model') or current_local_ai_model()
    cloud_model = settings.get('cloud_model') or settings.get('cloud_provider') or 'not configured'
    analyzed = sum(1 for report in reports if report.ai_status_key == 'analyzed')
    ready = bool(reports) and analyzed == len(reports)
    actionable = [
        report for report in reports
        if report.tuning_recommendation and report.tuning_recommendation not in {'none', 'n/a', 'needs_more_data'}
    ]
    repeated = sorted(
        [report for report in reports if report.repeat_count >= 3 and report not in actionable],
        key=lambda report: (report.repeat_count, report.criticality_rank),
        reverse=True,
    )[:4]
    current_rule_rows = ''.join(siem_engineering_tuning_row(report) for report in actionable[:10])
    new_rule_rows = ''.join(siem_engineering_detection_row(report) for report in repeated[:10])
    return f'''
    <section class="view-section active siem-engineering-view" aria-label="SIEM Engineering recommendations">
      <section class="siem-eng-hero">
        <div>
          <span class="settings-kicker">SIEM engineering</span>
          <h2>SIEM Engineer</h2>
          <p>Prioritized tuning and detection work.</p>
        </div>
        <div class="siem-model-card">
          <span>Model route</span>
          <strong>{html.escape(mode.title())}</strong>
          <em>Local: {html.escape(local_model)} · Cloud: {html.escape(cloud_model)}</em>
        </div>
      </section>
      <section class="siem-eng-kpis" aria-label="SIEM engineering readiness">
        <article><span>Gate</span><strong>{'Ready' if ready else 'Waiting'}</strong><em>{analyzed}/{len(reports)} analyzed</em></article>
        <article><span>Cadence</span><strong>6h</strong><em>after backlog clears</em></article>
        <article><span>Tuning</span><strong>{len(actionable)}</strong><em>current-rule ideas</em></article>
        <article><span>Detections</span><strong>{len(repeated)}</strong><em>new-rule ideas</em></article>
      </section>
      {siem_engineering_best_roi_section(reports)}
      {siem_engineering_table('Current rule tuning', '', current_rule_rows, 'No model-backed tuning recommendations yet.')}
      {siem_engineering_table('New detections', '', new_rule_rows, 'No repeated detection candidates yet.')}
    </section>'''


def query_part(value: str) -> str:
    cleaned = clean_endpoint_part(value)
    return '' if cleaned in {'n/a', 'unknown'} else cleaned


def kql_string(value: str) -> str:
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'


def sql_string(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def threat_hunt_queries(report: AlertReport) -> tuple[str, str, str]:
    rule = query_part(report.rule_name)
    src = query_part(report.source_ip)
    dst = query_part(report.destination_ip)
    port = query_part(report.destination_port)
    dataset = query_part(report.alert_source)
    kql_parts = []
    if rule:
        kql_parts.append(f'rule.name : {kql_string(rule)}')
    if dataset:
        kql_parts.append(f'event.dataset : {kql_string(dataset)}')
    if src:
        kql_parts.append(f'source.ip : {kql_string(src)}')
    if dst:
        kql_parts.append(f'destination.ip : {kql_string(dst)}')
    if port:
        kql_parts.append(f'destination.port : {port}' if port.isdigit() else f'destination.port : {kql_string(port)}')
    kql = ' and '.join(kql_parts) or f'rule.name : {kql_string(rule or report.title)}'
    oql_parts = []
    if rule:
        oql_parts.append(f'rule.name == {kql_string(rule)}')
    if dataset:
        oql_parts.append(f'event.dataset == {kql_string(dataset)}')
    if src:
        oql_parts.append(f'source.ip == {kql_string(src)}')
    if dst:
        oql_parts.append(f'destination.ip == {kql_string(dst)}')
    if port:
        oql_parts.append(f'destination.port == {port}' if port.isdigit() else f'destination.port == {kql_string(port)}')
    oql = ' AND '.join(oql_parts) or f'rule.name == {kql_string(rule or report.title)}'
    remote_filters = []
    if dst:
        remote_filters.append(f"remote_address = {sql_string(dst)}")
    if port and port.isdigit():
        remote_filters.append(f'remote_port = {port}')
    where = ' AND '.join(remote_filters) if remote_filters else "remote_address != ''"
    osquery = f"""SELECT
  pos.pid,
  p.name,
  p.path,
  pos.local_address,
  pos.local_port,
  pos.remote_address,
  pos.remote_port,
  pos.protocol
FROM process_open_sockets AS pos
LEFT JOIN processes AS p ON pos.pid = p.pid
WHERE {where}
ORDER BY p.name, pos.remote_address, pos.remote_port;"""
    return kql, oql, osquery


def threat_hunt_row(report: AlertReport, index: int) -> str:
    kql, oql, osquery = threat_hunt_queries(report)
    route = f'{report.source_ip} > {report.destination_ip} : {report.destination_port}'
    hypothesis = ai_summary_for(report)
    priority = 'Immediate' if report.criticality_rank >= 4 else 'Review'
    return f'''
    <tbody class="threat-hunt-group">
      <tr class="threat-hunt-row" tabindex="0" aria-expanded="false" data-hunt-toggle>
        <td><span class="severity-label severity-text-{html.escape(criticality_class(report.criticality))}">{html.escape(report.criticality)}</span></td>
        <td><strong>{html.escape(report.rule_name or report.title)}</strong><code>{html.escape(route)}</code></td>
        <td><span class="siem-table-pill">{priority}</span></td>
        <td class="hunt-hypothesis">{html.escape(hypothesis)}</td>
        <td><b>{report.repeat_count}</b><span>{html.escape(last_seen_iso_for(report))}</span></td>
      </tr>
      <tr class="threat-hunt-detail" hidden>
        <td colspan="5">
          <section class="hunt-detail-panel">
            <div class="hunt-detail-copy">
              <h3>Threat hunt details</h3>
              <p>Validate whether this detection is isolated noise, repeated reconnaissance, policy-expected traffic, or a pivot point for deeper endpoint and network review.</p>
              <dl>
                <div><dt>Observed route</dt><dd>{html.escape(route)}</dd></div>
                <div><dt>First seen</dt><dd>{html.escape(report.first_seen)}</dd></div>
                <div><dt>Last seen</dt><dd>{html.escape(last_seen_iso_for(report))}</dd></div>
                <div><dt>Evidence gap</dt><dd>Confirm endpoint owner, process context, authentication outcome, and whether related destinations appear in the same window.</dd></div>
              </dl>
            </div>
            <div class="hunt-query-grid">
              {threat_hunt_code_block('Elastic KQL', kql, f'hunt-{index}-kql')}
              {threat_hunt_code_block('Security Onion OQL', oql, f'hunt-{index}-oql')}
              {threat_hunt_code_block('OSQuery', osquery, f'hunt-{index}-osquery')}
            </div>
          </section>
        </td>
      </tr>
    </tbody>'''


def threat_hunt_code_block(title: str, code: str, block_id: str) -> str:
    return f'''
    <article class="hunt-code-card">
      <header><span>{html.escape(title)}</span><button type="button" data-copy-target="{html.escape(block_id)}">Copy</button></header>
      <pre><code id="{html.escape(block_id)}">{html.escape(code)}</code></pre>
    </article>'''


def threat_hunter_page_section(reports: list[AlertReport]) -> str:
    candidates = sorted(
        [report for report in reports if report.filter_status in {'accepted', 'escalated', 'unknown', 'suppressed'}],
        key=lambda report: (report.criticality_rank, report.repeat_count, last_seen_ts_for(report)),
        reverse=True,
    )[:12]
    rows = ''.join(threat_hunt_row(report, index) for index, report in enumerate(candidates, 1))
    if not rows:
        rows = '<tbody><tr class="siem-empty-row"><td colspan="5">No threat hunt candidates are available yet.</td></tr></tbody>'
    return f'''
    <section class="view-section active threat-hunter-view" aria-label="Threat Hunter workspace">
      <section class="threat-hunter-hero">
        <div>
          <span class="settings-kicker">Threat Hunter</span>
          <h2>Proposed threat hunts</h2>
          <p>Skimmable hunt ideas built from current grouped detections. Open a row to review the hypothesis, validation notes, and query-ready pivots.</p>
        </div>
      </section>
      <section class="siem-table-section" aria-label="Proposed threat hunts">
        <div class="siem-table-wrap">
          <table class="siem-engineering-table threat-hunt-table">
            <thead><tr><th>Severity</th><th>Hunt focus</th><th>Priority</th><th>Hypothesis</th><th>Activity</th></tr></thead>
            {rows}
          </table>
        </div>
      </section>
    </section>'''


def system_health_page_section() -> str:
    return '''
    <section class="view-section active system-health-view" aria-label="System Health">
      <section class="system-health-hero">
        <div>
          <span class="settings-kicker">Relay health</span>
          <h2>n8n beacon history</h2>
          <p>Last 24 hours of relay-to-n8n beacon activity, unsuccessful attempts, and successful-beacon gaps longer than 10 minutes.</p>
        </div>
        <button id="system-health-refresh" class="alerts-refresh" type="button" aria-label="Refresh System Health" title="Refresh System Health" aria-busy="false"><span class="alerts-refresh-icon" aria-hidden="true">↻</span></button>
      </section>
      <section class="system-health-kpis" aria-label="System Health summary">
        <article><span>Latest</span><strong id="health-latest">Checking...</strong><em id="health-latest-detail">Waiting for beacon history.</em></article>
        <article><span>Successful</span><strong id="health-successful">0</strong><em>beacons in 24 hours</em></article>
        <article><span>Unsuccessful</span><strong id="health-unsuccessful">0</strong><em>failed or recovery-marked events</em></article>
        <article><span>Gaps &gt;10m</span><strong id="health-gaps">0</strong><em>without a successful beacon</em></article>
      </section>
      <section class="system-health-panel" aria-label="Beacon gaps">
        <div class="system-health-panel-title"><h3>Beacon gaps</h3><span id="health-gap-note">No data loaded yet.</span></div>
        <div id="health-gap-list" class="health-gap-list"></div>
      </section>
      <section class="system-health-panel" aria-label="Beacon history">
        <div class="system-health-panel-title"><h3>Beacon events</h3><span id="health-event-note">Last 24 hours</span></div>
        <div class="system-health-table-wrap">
          <table class="system-health-table">
            <thead><tr><th>Time</th><th>Result</th><th>Stage</th><th>Relay</th><th>Alerts</th><th>HTTP</th><th>Details</th></tr></thead>
            <tbody id="health-beacon-rows"><tr><td colspan="7">Loading beacon history...</td></tr></tbody>
          </table>
        </div>
      </section>
    </section>'''


def enrichment_service_tiles() -> str:
    tiles = []
    for service in ENRICHMENT_FLOW_SERVICES:
        name = html.escape(service['name'])
        scope = html.escape(service['scope'])
        note = html.escape(service['note'])
        asset = service.get('asset') or ''
        if asset:
            icon = f'<span class="enrichment-logo"><img src="{html.escape(asset)}" alt="{name} logo"></span>'
        else:
            fallback = html.escape(service.get('fallback', name[:1]))
            icon = f'<span class="enrichment-logo enrichment-logo-fallback" aria-hidden="true">{fallback}</span>'
        tiles.append(
            f'''<article class="enrichment-service" aria-label="{name} enrichment service">
              {icon}
              <div><strong>{name}</strong><span>{scope}</span></div>
              <em>{note}</em>
            </article>'''
        )
    return '\n'.join(tiles)


def flow_page_section(reports: list[AlertReport]) -> str:
    local_model = html.escape(current_local_ai_model())
    total_groups = len(reports)
    total_observations = sum(max(1, int(report.repeat_count or 1)) for report in reports)
    analyzed_groups = sum(1 for report in reports if report.ai_status_key == 'analyzed')
    urgent_groups = sum(1 for report in reports if criticality_class(report.criticality) in {'critical', 'high'})
    ai_coverage = pct(analyzed_groups, total_groups)
    ai_markdown_reports = count_ai_analysis_artifacts('.md')
    ai_json_reports = count_ai_analysis_artifacts('.json')
    telegram_counts = telegram_sent_counts()
    enrichment_tiles = enrichment_service_tiles()
    return f'''
    <section id="overview-view" class="view-section overview-view active flow-page-view" aria-label="Autonomous SIEM alert enrichment data flow">
      <section class="flow-product-hero" aria-labelledby="flow-title">
        <button class="flow-privacy-toggle" type="button" aria-pressed="false" aria-label="Show node IP addresses" title="Show node IP addresses">
          <img src="assets/privacy-eye-button.png" alt="" aria-hidden="true">
        </button>
        <div class="flow-product-copy">
          <h2 id="flow-title">Autonomous SIEM Alert Enrichment & Threat Investigation</h2>
          <div class="flow-pulse-divider" aria-hidden="true"></div>
          <p>Alerts move from Security Onion through the relay into n8n. n8n calls alert-store enrichment, alert-store fans out only to configured public sources, then normalized evidence feeds SQLite, local AI, reports, Telegram, and the dashboard.</p>
        </div>
        <div class="flow-product-map" aria-label="Current Onion Sentinel data flow">
          <div class="flow-lane flow-lane-ingress" aria-label="Alert ingress">
            <article class="flow-system-node">
              <span class="flow-logo-ring"><img src="assets/brand/security-onion.svg" alt="Security Onion logo"></span>
              <div><strong>Security Onion</strong><span class="flow-ip-address" data-ip="192.168.1.7">xxx.xxx.xxx.xxx</span></div>
              <em>Restricted alert export</em>
            </article>
            <div class="flow-connector"><span>SSH poll</span></div>
            <article class="flow-system-node">
              <span class="flow-logo-ring"><img src="assets/brand/raspberry-pi.svg" alt="Raspberry Pi logo"></span>
              <div><strong>Raspberry Pi Relay</strong><span class="flow-ip-address" data-ip="10.88.8.8">xxx.xxx.xxx.xxx</span></div>
              <em>VLAN 888 transport</em>
            </article>
            <div class="flow-connector"><span>webhook</span></div>
            <article class="flow-system-node">
              <span class="flow-logo-ring"><img src="assets/brand/docker.svg" alt="Docker logo"></span>
              <div><strong>Docker</strong><span class="flow-ip-address" data-ip="10.77.7.225">xxx.xxx.xxx.xxx</span></div>
              <em>Mac Studio runtime</em>
            </article>
            <div class="flow-connector"><span>container net</span></div>
            <article class="flow-system-node">
              <span class="flow-logo-ring"><img src="assets/brand/n8n.svg" alt="n8n logo"></span>
              <div><strong>n8n Workflow</strong><span>:5678 webhook + heartbeat</span></div>
              <em>validate, call enrichment</em>
            </article>
          </div>

          <div class="flow-downlink"><span>dedicated enrichment stage: POST /enrich before /alert storage</span></div>

          <section class="flow-enrichment-band" aria-label="Alert enrichment service layer">
            <article class="flow-system-node flow-enrichment-core">
              <span class="flow-logo-ring"><span>API</span></span>
              <div>
                <strong>alert-store enrichment</strong>
                <span>API-key gating, privacy checks, SQLite cache, rate limits</span>
              </div>
              <em>cache + normalize intel</em>
            </article>
            <div class="enrichment-service-grid" aria-label="Configured enrichment service catalog">
              {enrichment_tiles}
            </div>
          </section>

          <div class="flow-downlink"><span>POST /alert: score, dedupe, suppress, notify, store</span></div>

          <section class="flow-output-band" aria-label="Mac Studio hosted outputs and external notification">
            <section class="flow-mac-cluster" aria-label="Mac Studio hosted state analysis and dashboard services">
              <div class="flow-cluster-heading">
                <span class="flow-logo-ring"><img src="assets/brand/apple.svg" alt="Apple logo"></span>
                <div>
                  <strong>Mac Studio AI Lab</strong>
                  <span><span class="flow-ip-address" data-ip="10.77.7.225">xxx.xxx.xxx.xxx</span> hosted services</span>
                </div>
              </div>
              <div class="flow-cluster-grid">
                <article class="flow-system-node">
                  <span class="flow-logo-ring"><img src="assets/brand/sqlite.svg" alt="SQLite logo"></span>
                  <div>
                    <strong>SQLite</strong><span>alert-store backend</span>
                    <div class="flow-format-metrics" aria-label="SQLite alert-store metrics">
                      <span><b>{total_groups}</b><em>Grouped</em></span>
                      <span><b>{total_observations}</b><em>Observations</em></span>
                    </div>
                  </div>
                  <em>dashboard source</em>
                </article>
                <article class="flow-system-node">
                  <span class="flow-logo-ring"><img src="assets/brand/ollama.svg" alt="Ollama logo"></span>
                  <div><strong>Ollama</strong><span>{local_model}</span></div>
                  <em>local model analysis</em>
                </article>
                <article class="flow-system-node">
                  <div class="flow-logo-pair" aria-label="AI report output formats">
                    <span class="flow-logo-ring"><img src="assets/brand/obsidian.svg" alt="Obsidian logo"></span>
                    <span class="flow-logo-ring"><img src="assets/brand/json.svg" alt="JSON logo"></span>
                  </div>
                  <div>
                    <strong>AI Reports</strong><span>Markdown + JSON artifacts</span>
                    <div class="flow-format-metrics" aria-label="AI report artifact formats">
                      <span><b>{ai_markdown_reports}</b><em>Markdown</em></span>
                      <span><b>{ai_json_reports}</b><em>JSON</em></span>
                    </div>
                  </div>
                  <em>findings + actions</em>
                </article>
                <article class="flow-system-node flow-dashboard-node">
                  <span class="flow-logo-ring"><img src="assets/onion-sentinel-logo.png" alt="Onion Sentinel logo"></span>
                  <div><strong>Onion Sentinel</strong><span>SOC analyst dashboard</span></div>
                  <div class="flow-node-metrics" aria-label="Onion Sentinel dashboard metrics">
                    <span><b>{total_groups}</b><em>Grouped</em></span>
                    <span><b>{total_observations}</b><em>Observations</em></span>
                    <span><b>{ai_coverage}%</b><em>AI coverage</em></span>
                    <span><b>{urgent_groups}</b><em>Critical/high</em></span>
                  </div>
                  <em>triage UI</em>
                </article>
              </div>
            </section>
            <section class="flow-external-cluster" aria-label="External notification delivery">
              <div class="flow-cluster-heading">
                <span class="flow-logo-ring"><img src="assets/brand/telegram.svg" alt="Telegram logo"></span>
                <div>
                  <strong>External notification</strong>
                  <span>High-signal mobile alerts</span>
                </div>
              </div>
              <article class="flow-system-node">
                <span class="flow-logo-ring"><img src="assets/brand/telegram.svg" alt="Telegram logo"></span>
                <div>
                  <strong>Telegram</strong><span>High and critical alerts</span>
                  <div class="flow-format-metrics" aria-label="Telegram notification metrics">
                    <span><b>{telegram_counts['critical']}</b><em>Critical</em></span>
                    <span><b>{telegram_counts['high']}</b><em>High</em></span>
                  </div>
                </div>
                <em>notification</em>
              </article>
            </section>
          </section>
        </div>
      </section>
      <section class="flow-summary-grid" aria-label="Pipeline service summary">
        <div class="flow-summary-card"><span>Source</span><strong>Security Onion</strong><em>Restricted export wrapper</em></div>
        <div class="flow-summary-card"><span>Relay</span><strong>Raspberry Pi</strong><em>5 minute timer</em></div>
        <div class="flow-summary-card"><span>Runtime</span><strong>Docker</strong><em>n8n container</em></div>
        <div class="flow-summary-card"><span>Workflow</span><strong>n8n</strong><em>Validation and enrichment callout</em></div>
        <div class="flow-summary-card"><span>Enrichment</span><strong>alert-store</strong><em>Keys, cache, rate limits</em></div>
        <div class="flow-summary-card"><span>Local LLM</span><strong>Ollama</strong><em>{local_model}</em></div>
        <div class="flow-summary-card"><span>Outputs</span><strong>SQLite + Telegram</strong><em>Dashboard store and phone alerts</em></div>
      </section>
    </section>'''


def settings_page_section() -> str:
    prompt = html.escape(load_soc_analyst_prompt())
    prompt_path = html.escape(display_path(SOC_ANALYST_PROMPT_FILE))
    analyst_memory_path = html.escape(display_path(SOC_ANALYST_MEMORY_FILE))
    shared_memory_path = html.escape(display_path(SHARED_AGENT_MEMORY_FILE))
    engineer_prompt = html.escape(load_siem_engineer_prompt())
    engineer_prompt_path = html.escape(display_path(SIEM_ENGINEER_PROMPT_FILE))
    engineer_memory_path = html.escape(display_path(SIEM_ENGINEER_MEMORY_FILE))
    hunter_prompt = html.escape(load_threat_hunter_prompt())
    hunter_prompt_path = html.escape(display_path(THREAT_HUNTER_PROMPT_FILE))
    hunter_memory_path = html.escape(display_path(THREAT_HUNTER_MEMORY_FILE))
    intel_prompt = html.escape(load_cyber_threat_intel_prompt())
    intel_prompt_path = html.escape(display_path(CYBER_THREAT_INTEL_PROMPT_FILE))
    intel_memory_path = html.escape(display_path(CYBER_THREAT_INTEL_MEMORY_FILE))
    incident_prompt = html.escape(load_incident_responder_prompt())
    incident_prompt_path = html.escape(display_path(INCIDENT_RESPONDER_PROMPT_FILE))
    incident_memory_path = html.escape(display_path(INCIDENT_RESPONDER_MEMORY_FILE))
    ai_settings = load_soc_ai_settings()
    ai_path = html.escape(display_path(SOC_AI_SETTINGS_FILE))
    mode = ai_settings['mode']
    hybrid_policy = ai_settings['hybrid_policy']
    model_options = ollama_model_options(ai_settings['ollama_model'])
    return f'''
    <section class="view-section active settings-view" aria-label="SOC workflow settings">
      <details class="settings-panel settings-details settings-model-details" aria-labelledby="soc-ai-model-title">
        <summary>
          <span class="settings-summary-main">
            <span class="settings-summary-icon" aria-hidden="true"><img src="assets/settings-ai-model-routing.png" alt=""></span>
            <span class="settings-summary-copy">
              <span class="settings-kicker">AI model routing</span>
              <strong id="soc-ai-model-title">AI Analysis Model Selection</strong>
            </span>
          </span>
          <code>{ai_path}</code>
        </summary>
        <div class="settings-panel-top">
          <div>
            <p>Choose whether alert analysis uses local Ollama, a configured frontier/cloud CLI, or a local-first hybrid path.</p>
          </div>
        </div>
        <section class="settings-subsection settings-subsection-primary" aria-labelledby="analysis-mode-title">
          <div class="settings-subsection-head">
            <span class="settings-step-badge">1</span>
            <div>
              <span class="settings-kicker">Analysis mode</span>
              <h3 id="analysis-mode-title">Choose the analysis path</h3>
              <p>Start here. This decides whether every alert goes to local Ollama, a frontier/cloud CLI, or a local-first hybrid route.</p>
            </div>
          </div>
          <label class="settings-field settings-field-wide">Analysis mode
            <select id="ai-analysis-mode">
              <option value="ollama" {'selected' if mode == 'ollama' else ''}>Ollama local only</option>
              <option value="cloud" {'selected' if mode == 'cloud' else ''}>Frontier cloud CLI only</option>
              <option value="hybrid" {'selected' if mode == 'hybrid' else ''}>Hybrid local-first</option>
            </select>
          </label>
        </section>
        <section class="settings-subsection" aria-labelledby="ollama-settings-title">
          <div class="settings-subsection-head">
            <span class="settings-step-badge">2</span>
            <div>
              <span class="settings-kicker">Ollama local LLM</span>
              <h3 id="ollama-settings-title">Configure local analysis</h3>
              <p>Pick the local model that should handle private first-pass SOC analysis.</p>
            </div>
          </div>
          <div class="settings-grid settings-grid-two">
          <label class="settings-field">Ollama model
            <select id="ai-ollama-model" data-selected-model="{html.escape(ai_settings['ollama_model'])}">
              {model_options}
            </select>
          </label>
          <label class="settings-field">Ollama URL
            <input id="ai-ollama-url" type="text" value="{html.escape(ai_settings['ollama_url'])}" placeholder="http://127.0.0.1:11434">
          </label>
          </div>
          <div class="settings-note">The model dropdown is populated from <code>ollama ls</code> and refreshes from the portal API every 60 seconds while this page is open.</div>
        </section>
        <section class="settings-subsection" aria-labelledby="cloud-provider-title">
          <div class="settings-subsection-head">
            <span class="settings-step-badge">3</span>
            <div>
              <span class="settings-kicker">Frontier cloud model</span>
              <h3 id="cloud-provider-title">Configure frontier escalation</h3>
              <p>Use this only when cloud or hybrid mode needs a second-opinion model through a local CLI.</p>
            </div>
          </div>
          <div class="settings-grid">
          <label class="settings-field">Cloud provider label
            <input id="ai-cloud-provider" type="text" value="{html.escape(ai_settings['cloud_provider'])}" placeholder="gpt-cli">
          </label>
          <label class="settings-field">Cloud model
            <input id="ai-cloud-model" type="text" value="{html.escape(ai_settings['cloud_model'])}" placeholder="frontier model name">
          </label>
          <label class="settings-field settings-field-wide">Cloud CLI command
            <input id="ai-cloud-command" type="text" value="{html.escape(ai_settings['cloud_command'])}" placeholder="command that reads JSON stdin and returns analysis JSON stdout">
          </label>
          <label class="settings-field settings-field-wide">Hybrid policy
            <select id="ai-hybrid-policy">
              <option value="cloud_for_critical_high_or_recommended" {'selected' if hybrid_policy == 'cloud_for_critical_high_or_recommended' else ''}>Use cloud for Critical/High or when local recommends it</option>
              <option value="cloud_when_recommended_only" {'selected' if hybrid_policy == 'cloud_when_recommended_only' else ''}>Use cloud only when local recommends it</option>
            </select>
          </label>
          </div>
          <div class="settings-note">Cloud and hybrid mode require a configured local CLI command. The command receives a bounded JSON prompt package on stdin and must return one valid analysis JSON object on stdout.</div>
        </section>
        <div class="settings-actions">
          <button id="save-ai-model-settings" class="settings-save-button" type="button">Save Model Settings</button>
          <span id="ai-model-settings-status" class="settings-save-status" role="status" aria-live="polite"></span>
        </div>
      </details>
      <section class="settings-agent-section" aria-labelledby="cyber-security-agents-title">
        <div class="settings-agent-heading">
          <span class="settings-kicker">Agent prompts</span>
          <h2 id="cyber-security-agents-title">Cyber Security Agents</h2>
        </div>
      <details class="settings-panel settings-details" aria-labelledby="soc-analyst-prompt-title">
        <summary>
          <span class="settings-summary-main">
            <span class="settings-summary-icon" aria-hidden="true"><img src="assets/settings-soc-analyst-prompt.png" alt=""></span>
            <span class="settings-summary-copy">
              <span class="settings-kicker">SOC analyst prompt</span>
              <strong id="soc-analyst-prompt-title">SOC Analyst System Prompt</strong>
              <span class="settings-trigger-line">Trigger: new eligible alert; scheduled AI worker drains highest severity newest first.</span>
            </span>
          </span>
          <span class="settings-path-stack" aria-label="SOC Analyst files">
            <span><b>Prompt</b><code>{prompt_path}</code></span>
            <span><b>Memory</b><code>{analyst_memory_path}</code></span>
            <span><b>Shared</b><code>{shared_memory_path}</code></span>
          </span>
        </summary>
        <div class="settings-panel-top">
          <div>
            <p>This prompt is sent as the system message when the local AI model analyzes Security Onion alerts.</p>
          </div>
        </div>
        <label class="prompt-editor-label" for="soc-analyst-prompt">Prompt body</label>
        <textarea id="soc-analyst-prompt" class="prompt-editor" spellcheck="false">{prompt}</textarea>
        <div class="settings-actions">
          <button id="save-soc-analyst-prompt" class="settings-save-button" type="button">Save</button>
          <span id="soc-analyst-prompt-status" class="settings-save-status" role="status" aria-live="polite"></span>
        </div>
      </details>
      <details class="settings-panel settings-details" aria-labelledby="incident-responder-prompt-title">
        <summary>
          <span class="settings-summary-main">
            <span class="settings-summary-icon" aria-hidden="true"><img src="assets/settings-incident-responder-prompt.png" alt=""></span>
            <span class="settings-summary-copy">
              <span class="settings-kicker">Incident responder prompt</span>
              <strong id="incident-responder-prompt-title">Incident Responder</strong>
              <span class="settings-trigger-line">Trigger: manual incident workflow now; external IR host collection is TODO.</span>
            </span>
          </span>
          <span class="settings-path-stack" aria-label="Incident Responder files">
            <span><b>Prompt</b><code>{incident_prompt_path}</code></span>
            <span><b>Memory</b><code>{incident_memory_path}</code></span>
            <span><b>Shared</b><code>{shared_memory_path}</code></span>
          </span>
        </summary>
        <div class="settings-panel-top">
          <div>
            <p>This prompt guides senior incident response planning, evidence preservation, containment guidance, and future host artifact collection workflows.</p>
          </div>
        </div>
        <div class="settings-note">TODO: connect the dedicated incident response host before allowing this agent to trigger external host artifact collection scripts. Until then, recommendations should mark those actions as pending integration.</div>
        <label class="prompt-editor-label" for="incident-responder-prompt">Prompt body</label>
        <textarea id="incident-responder-prompt" class="prompt-editor" spellcheck="false">{incident_prompt}</textarea>
        <div class="settings-actions">
          <button id="save-incident-responder-prompt" class="settings-save-button" type="button">Save</button>
          <span id="incident-responder-prompt-status" class="settings-save-status" role="status" aria-live="polite"></span>
        </div>
      </details>
      <details class="settings-panel settings-details" aria-labelledby="siem-engineer-prompt-title">
        <summary>
          <span class="settings-summary-main">
            <span class="settings-summary-icon" aria-hidden="true"><img src="assets/settings-siem-engineer-prompt.png" alt=""></span>
            <span class="settings-summary-copy">
              <span class="settings-kicker">SIEM engineer prompt</span>
              <strong id="siem-engineer-prompt-title">SIEM Engineer System Prompt</strong>
              <span class="settings-trigger-line">Planned trigger: cron every 6 hours after all eligible alerts are analyzed.</span>
            </span>
          </span>
          <span class="settings-path-stack" aria-label="SIEM Engineer files">
            <span><b>Prompt</b><code>{engineer_prompt_path}</code></span>
            <span><b>Memory</b><code>{engineer_memory_path}</code></span>
            <span><b>Shared</b><code>{shared_memory_path}</code></span>
          </span>
        </summary>
        <div class="settings-panel-top">
          <div>
            <p>This prompt guides the SIEM Engineering review that recommends scoped tuning and new detection work after all eligible alerts have finished AI analysis.</p>
          </div>
        </div>
        <div class="settings-note">Designed cadence: every 6 hours, only when the alert analysis backlog is clear. It should review alerts, enrichments, notes, acknowledgments, suppressions, and related detection context before recommending changes.</div>
        <label class="prompt-editor-label" for="siem-engineer-prompt">Prompt body</label>
        <textarea id="siem-engineer-prompt" class="prompt-editor" spellcheck="false">{engineer_prompt}</textarea>
        <div class="settings-actions">
          <button id="save-siem-engineer-prompt" class="settings-save-button" type="button">Save</button>
          <span id="siem-engineer-prompt-status" class="settings-save-status" role="status" aria-live="polite"></span>
        </div>
      </details>
      <details class="settings-panel settings-details" aria-labelledby="cyber-threat-intel-prompt-title">
        <summary>
          <span class="settings-summary-main">
            <span class="settings-summary-icon" aria-hidden="true"><img src="assets/settings-cyber-threat-intel-prompt.svg" alt=""></span>
            <span class="settings-summary-copy">
              <span class="settings-kicker">Cyber threat intel prompt</span>
              <strong id="cyber-threat-intel-prompt-title">Cyber Threat Intel Analyst</strong>
              <span class="settings-trigger-line">Trigger: manual intel review from alerts, enrichments, hunts, and engineering context; scheduled briefs are future work.</span>
            </span>
          </span>
          <span class="settings-path-stack" aria-label="Cyber Threat Intel Analyst files">
            <span><b>Prompt</b><code>{intel_prompt_path}</code></span>
            <span><b>Memory</b><code>{intel_memory_path}</code></span>
            <span><b>Shared</b><code>{shared_memory_path}</code></span>
          </span>
        </summary>
        <div class="settings-panel-top">
          <div>
            <p>This prompt guides intelligence briefs, indicator review, enrichment pivots, confidence scoring, and cross-agent context for SOC decisions.</p>
          </div>
        </div>
        <label class="prompt-editor-label" for="cyber-threat-intel-prompt">Prompt body</label>
        <textarea id="cyber-threat-intel-prompt" class="prompt-editor" spellcheck="false">{intel_prompt}</textarea>
        <div class="settings-actions">
          <button id="save-cyber-threat-intel-prompt" class="settings-save-button" type="button">Save</button>
          <span id="cyber-threat-intel-prompt-status" class="settings-save-status" role="status" aria-live="polite"></span>
        </div>
      </details>
      <details class="settings-panel settings-details" aria-labelledby="threat-hunter-prompt-title">
        <summary>
          <span class="settings-summary-main">
            <span class="settings-summary-icon" aria-hidden="true"><img src="assets/settings-threat-hunter-prompt.png" alt=""></span>
            <span class="settings-summary-copy">
              <span class="settings-kicker">Threat hunter prompt</span>
              <strong id="threat-hunter-prompt-title">Threat Hunter System Prompt</strong>
              <span class="settings-trigger-line">Trigger: manual hunt review from alert patterns; automated hunts are future work.</span>
            </span>
          </span>
          <span class="settings-path-stack" aria-label="Threat Hunter files">
            <span><b>Prompt</b><code>{hunter_prompt_path}</code></span>
            <span><b>Memory</b><code>{hunter_memory_path}</code></span>
            <span><b>Shared</b><code>{shared_memory_path}</code></span>
          </span>
        </summary>
        <div class="settings-panel-top">
          <div>
            <p>This prompt guides senior threat-hunt recommendations, including Security Onion pivots and query-ready KQL, OQL, and OSQuery hunt plans.</p>
          </div>
        </div>
        <label class="prompt-editor-label" for="threat-hunter-prompt">Prompt body</label>
        <textarea id="threat-hunter-prompt" class="prompt-editor" spellcheck="false">{hunter_prompt}</textarea>
        <div class="settings-actions">
          <button id="save-threat-hunter-prompt" class="settings-save-button" type="button">Save</button>
          <span id="threat-hunter-prompt-status" class="settings-save-status" role="status" aria-live="polite"></span>
        </div>
      </details>
      </section>
    </section>'''


EXECUTIVE_HOME_CSS = '''
<style>
.executive-home-view{display:block;padding-top:14px}.exec-hero{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin-bottom:16px;border:1px solid rgba(148,163,184,.14);border-radius:14px;padding:20px;background:linear-gradient(135deg,#0d1620 0%,#101923 58%,#0b131c 100%);box-shadow:0 22px 48px rgba(0,0,0,.24),inset 0 1px 0 rgba(255,255,255,.035)}.exec-kicker{display:inline-block;border:1px solid rgba(34,211,238,.28);border-radius:999px;padding:6px 10px;color:#8ff4ff;background:rgba(34,211,238,.06);font-size:11px;font-weight:950;text-transform:uppercase;letter-spacing:.12em}.exec-hero h2{margin:14px 0 8px;color:#f5f9ff;font-size:34px;line-height:1;letter-spacing:-.04em}.exec-hero p{max-width:68ch;margin:0;color:#9aaabd;font-size:14px;line-height:1.55}.exec-hero-stamp{min-width:210px;border:1px solid rgba(34,211,238,.16);border-radius:12px;padding:14px 16px;background:#071018;text-align:right}.exec-hero-stamp span,.exec-kpi span,.exec-card-title span{display:block;color:#8ff4ff;font-size:11px;font-weight:950;text-transform:uppercase;letter-spacing:.11em}.exec-hero-stamp strong{display:block;margin-top:7px;color:#f3f8ff;font-size:14px}.exec-kpi-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:14px;margin-bottom:18px}.exec-kpi,.exec-card{border:1px solid rgba(148,163,184,.13);border-radius:12px;background:#0d1620;box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}.exec-kpi{min-height:120px;padding:18px}.exec-kpi strong{display:block;margin-top:10px;color:#f7fbff;font-size:34px;line-height:1;letter-spacing:0}.exec-kpi em{display:block;margin-top:8px;color:#9aa8b8;font-size:12px;font-style:normal;line-height:1.35}.exec-chart-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px}.exec-card{min-height:286px;padding:18px 20px;overflow:hidden}.exec-card-title{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;min-height:38px;margin-bottom:14px}.exec-card-title b{max-width:150px;color:#f4f8ff;font-size:13px;line-height:1.25;text-align:right}.donut-layout{display:grid;grid-template-columns:128px minmax(0,1fr);gap:16px;align-items:center}.donut-wrap{position:relative;width:128px;height:128px}.donut-chart{width:128px;height:128px;transform:rotate(-90deg);overflow:visible}.donut-track{fill:none;stroke:rgba(148,163,184,.12);stroke-width:4}.donut-segment{fill:none;stroke-width:4;stroke-linecap:round}.donut-center{position:absolute;inset:0;display:grid;place-items:center;color:#f5f9ff;font-size:24px;font-weight:950}.donut-legend{display:grid;gap:8px;min-width:0}.donut-legend span{display:flex;align-items:center;gap:7px;color:#aeb9c7;font-size:12px;min-width:0}.donut-legend b{color:#f4f8ff}.legend-dot{width:8px;height:8px;border-radius:999px;flex:0 0 8px}.donut-critical,.donut-bg-critical{stroke:var(--red);background:var(--red)}.donut-high,.donut-bg-high{stroke:var(--orange);background:var(--orange)}.donut-medium,.donut-bg-medium{stroke:var(--amber);background:var(--amber)}.donut-low,.donut-bg-low{stroke:#86efac;background:#86efac}.donut-informational,.donut-bg-informational,.donut-info,.donut-bg-info{stroke:#93c5fd;background:#93c5fd}.donut-accepted,.donut-bg-accepted,.donut-cyan,.donut-bg-cyan{stroke:var(--cyan);background:var(--cyan)}.donut-suppressed,.donut-bg-suppressed{stroke:#a78bfa;background:#a78bfa}.donut-escalated,.donut-bg-escalated{stroke:var(--red);background:var(--red)}.donut-stored,.donut-bg-stored{stroke:#94a3b8;background:#94a3b8}.donut-other,.donut-bg-other{stroke:#64748b;background:#64748b}.donut-green,.donut-bg-green{stroke:var(--green);background:var(--green)}.donut-amber,.donut-bg-amber{stroke:var(--amber);background:var(--amber)}.exec-bars{display:grid;gap:10px;min-width:0}.exec-bar-row{display:grid;grid-template-columns:minmax(108px,1.05fr) minmax(64px,.9fr) minmax(66px,max-content);gap:10px;align-items:center;min-width:0}.exec-bar-label{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#dce8f7;font-size:12px;font-weight:800}.exec-bar-track{min-width:0;height:9px;border-radius:999px;background:rgba(148,163,184,.10);overflow:hidden}.exec-bar-track span{display:block;height:100%;border-radius:999px;background:linear-gradient(90deg,rgba(34,211,238,.55),rgba(143,244,255,.95));box-shadow:0 0 12px rgba(34,211,238,.22)}.exec-bar-value{min-width:66px;color:#8ff4ff;font-size:12px;font-weight:950;text-align:right;font-variant-numeric:tabular-nums}@media(max-width:1500px){.exec-chart-grid{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:1300px){.exec-kpi-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.exec-chart-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:760px){.exec-hero{display:grid}.exec-hero-stamp{text-align:left;min-width:0}.exec-kpi-grid,.exec-chart-grid{grid-template-columns:1fr}.donut-layout{grid-template-columns:1fr;justify-items:center}.donut-legend{width:100%}.exec-bar-row{grid-template-columns:minmax(0,1fr) minmax(64px,.8fr) minmax(56px,max-content)}.exec-bar-value{min-width:56px}}
</style>
'''


SETTINGS_PAGE_CSS = '''
<style>
.settings-view{display:grid;gap:18px;padding-top:10px}.settings-agent-section{display:grid;gap:18px;max-width:1180px;margin-top:30px}.settings-agent-heading{padding:0 4px 2px}.settings-agent-heading h2{margin:7px 0 0;color:#f4f8ff;font-size:24px;line-height:1;letter-spacing:-.03em}.settings-panel{max-width:1180px;border:1px solid rgba(34,211,238,.18);border-radius:16px;padding:22px;background:linear-gradient(180deg,#0d1620,#09111a);box-shadow:0 22px 48px rgba(0,0,0,.24),inset 0 1px 0 rgba(255,255,255,.035)}.settings-panel-top{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;margin-bottom:18px}.settings-kicker{display:inline-block;color:#8ff4ff;font-size:11px;font-weight:950;text-transform:uppercase;letter-spacing:.13em}.settings-panel h2{margin:8px 0 6px;color:#f4f8ff;font-size:26px;letter-spacing:-.035em}.settings-panel h3{margin:5px 0 5px;color:#f4f8ff;font-size:18px;letter-spacing:-.025em}.settings-panel p{max-width:76ch;margin:0;color:#9aa8b8;font-size:13px;line-height:1.55}.settings-panel code{max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;border:1px solid rgba(148,163,184,.14);border-radius:10px;padding:8px 10px;color:#8ff4ff;background:#071018;font-size:12px}.settings-panel:not(.settings-details){position:relative}.settings-panel:not(.settings-details):before{content:'';position:absolute;left:43px;top:132px;bottom:84px;width:1px;background:linear-gradient(180deg,rgba(34,211,238,.45),rgba(34,211,238,.08));pointer-events:none}.settings-subsection{position:relative;border:1px solid rgba(148,163,184,.14);border-radius:15px;padding:18px 18px 18px 54px;margin-top:16px;background:linear-gradient(180deg,rgba(11,24,34,.74),rgba(7,16,24,.56));box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}.settings-subsection-primary{border-color:rgba(34,211,238,.36);background:linear-gradient(180deg,rgba(34,211,238,.09),rgba(7,16,24,.62));box-shadow:0 0 0 1px rgba(34,211,238,.035),inset 0 1px 0 rgba(255,255,255,.035)}.settings-subsection:after{content:'';position:absolute;left:25px;bottom:-17px;width:1px;height:17px;background:rgba(34,211,238,.22)}.settings-subsection:last-of-type:after{display:none}.settings-step-badge{position:absolute;left:18px;top:20px;display:grid;place-items:center;width:32px;height:32px;border:1px solid rgba(34,211,238,.45);border-radius:999px;color:#071018;background:#8ff4ff;font-size:13px;font-weight:950;box-shadow:0 0 22px rgba(34,211,238,.20)}.settings-subsection-head{display:grid;grid-template-columns:1fr;gap:8px;margin-bottom:16px}.settings-subsection-head p{max-width:68ch;color:#9fb0c4}.settings-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin-top:0}.settings-grid-two{grid-template-columns:repeat(2,minmax(0,1fr))}.settings-field{display:grid;gap:7px;min-width:0;color:#c9d6e6;font-size:12px;font-weight:900;text-transform:uppercase;letter-spacing:.08em}.settings-field-wide{grid-column:span 3}.settings-subsection-primary .settings-field-wide{grid-column:1 / -1}.settings-field input,.settings-field select{width:100%;min-width:0;border:1px solid rgba(34,211,238,.22);border-radius:12px;padding:12px 13px;color:#dce9f8;background:#071018;font:13px/1.3 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;outline:none;box-shadow:inset 0 0 18px rgba(34,211,238,.03);text-transform:none;letter-spacing:0}.settings-field input:focus,.settings-field select:focus{border-color:rgba(34,211,238,.70);box-shadow:0 0 0 3px rgba(34,211,238,.10),inset 0 0 20px rgba(34,211,238,.055)}.settings-note{margin-top:14px;border:1px solid rgba(246,199,109,.16);border-radius:12px;padding:12px 13px;color:#b8c6d8;background:rgba(246,199,109,.045);font-size:12px;line-height:1.5}.settings-note code{padding:2px 6px;max-width:none}.settings-details{padding:0;overflow:hidden}.settings-details summary{list-style:none;display:flex;align-items:center;justify-content:space-between;gap:14px;padding:16px 20px;cursor:pointer}.settings-details summary::-webkit-details-marker{display:none}.settings-summary-main{display:grid;grid-template-columns:56px minmax(0,1fr);align-items:center;gap:16px;min-width:0;flex:1}.settings-summary-icon{width:56px;height:56px;display:grid;place-items:center;flex:0 0 56px}.settings-summary-icon img{display:block;width:56px;height:56px;object-fit:contain;filter:drop-shadow(0 0 10px rgba(34,211,238,.24))}.settings-summary-copy{min-width:0}.settings-summary-copy .settings-kicker{display:block}.settings-trigger-line{display:block;margin-top:6px;color:#91a4ba;font-size:12px;font-weight:750;line-height:1.35;letter-spacing:0;overflow-wrap:anywhere}.settings-path-stack{display:grid;gap:7px;min-width:280px;max-width:520px;flex:0 1 520px}.settings-path-stack span{display:grid;grid-template-columns:58px minmax(0,1fr);align-items:center;gap:8px;min-width:0}.settings-path-stack b{color:#91a4ba;font-size:10px;font-weight:950;text-transform:uppercase;letter-spacing:.1em;text-align:right}.settings-path-stack code{max-width:100%;min-width:0}.settings-details summary:before{content:'▸';color:#8ff4ff;font-size:14px;transition:transform .16s ease}.settings-details[open] summary:before{transform:rotate(90deg)}.settings-details summary strong{display:block;margin-top:7px;color:#f4f8ff;font-size:20px;letter-spacing:-.025em}.settings-details[open]{padding-bottom:20px}.settings-details[open] .settings-panel-top,.settings-details[open] .prompt-editor-label,.settings-details[open] .prompt-editor,.settings-details[open] .settings-actions{margin-left:20px;margin-right:20px}.prompt-editor-label{display:block;margin:18px 0 8px;color:#c9d6e6;font-size:12px;font-weight:900;text-transform:uppercase;letter-spacing:.08em}.prompt-editor{display:block;width:calc(100% - 40px);min-height:520px;resize:vertical;border:1px solid rgba(34,211,238,.22);border-radius:12px;padding:16px 18px;color:#dce9f8;background:#071018;font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;outline:none;box-shadow:inset 0 0 24px rgba(34,211,238,.035)}.prompt-editor:focus{border-color:rgba(34,211,238,.70);box-shadow:0 0 0 3px rgba(34,211,238,.10),inset 0 0 24px rgba(34,211,238,.055)}.settings-actions{display:flex;align-items:center;gap:12px;margin-top:16px}.settings-save-button{border:1px solid rgba(34,211,238,.55);border-radius:12px;padding:10px 18px;color:#061018;background:#8ff4ff;font-weight:950;cursor:pointer;box-shadow:0 0 18px rgba(34,211,238,.18)}.settings-save-button:hover{background:#b8fbff;box-shadow:0 0 26px rgba(34,211,238,.34)}.settings-save-button:disabled{cursor:wait;opacity:.72}.settings-save-status{color:#9fb0c4;font-size:13px}.settings-save-status.ok{color:#8ff4ff}.settings-save-status.error{color:#fb7185}@media(max-width:980px){.settings-grid,.settings-grid-two{grid-template-columns:1fr}.settings-field-wide{grid-column:auto}.settings-panel:not(.settings-details):before{display:none}.settings-subsection{padding-left:18px;padding-top:60px}.settings-step-badge{left:18px;top:18px}.settings-subsection:after{display:none}}@media(max-width:760px){.settings-panel-top,.settings-details summary{display:grid}.settings-details summary{grid-template-columns:auto minmax(0,1fr);align-items:center}.settings-details summary code,.settings-path-stack{grid-column:1 / -1}.settings-summary-main{grid-template-columns:44px minmax(0,1fr);gap:12px}.settings-summary-icon,.settings-summary-icon img{width:44px;height:44px}.settings-panel code{max-width:100%}.settings-path-stack{max-width:100%;width:100%}.settings-path-stack b{text-align:left}.prompt-editor{min-height:420px}}
</style>
'''
SETTINGS_PAGE_JS = '''
<script>
(() => {
  const editor = document.querySelector('#soc-analyst-prompt');
  const saveButton = document.querySelector('#save-soc-analyst-prompt');
  const status = document.querySelector('#soc-analyst-prompt-status');
  const engineerEditor = document.querySelector('#siem-engineer-prompt');
  const saveEngineerButton = document.querySelector('#save-siem-engineer-prompt');
  const engineerStatus = document.querySelector('#siem-engineer-prompt-status');
  const hunterEditor = document.querySelector('#threat-hunter-prompt');
  const saveHunterButton = document.querySelector('#save-threat-hunter-prompt');
  const hunterStatus = document.querySelector('#threat-hunter-prompt-status');
  const intelEditor = document.querySelector('#cyber-threat-intel-prompt');
  const saveIntelButton = document.querySelector('#save-cyber-threat-intel-prompt');
  const intelStatus = document.querySelector('#cyber-threat-intel-prompt-status');
  const incidentEditor = document.querySelector('#incident-responder-prompt');
  const saveIncidentButton = document.querySelector('#save-incident-responder-prompt');
  const incidentStatus = document.querySelector('#incident-responder-prompt-status');
  const aiMode = document.querySelector('#ai-analysis-mode');
  const ollamaModel = document.querySelector('#ai-ollama-model');
  const ollamaUrl = document.querySelector('#ai-ollama-url');
  const cloudProvider = document.querySelector('#ai-cloud-provider');
  const cloudModel = document.querySelector('#ai-cloud-model');
  const cloudCommand = document.querySelector('#ai-cloud-command');
  const hybridPolicy = document.querySelector('#ai-hybrid-policy');
  const saveAiButton = document.querySelector('#save-ai-model-settings');
  const aiStatus = document.querySelector('#ai-model-settings-status');
  function setStatus(message, kind = '') {
    if (!status) return;
    status.textContent = message;
    status.className = `settings-save-status ${kind}`.trim();
  }
  function setAiStatus(message, kind = '') {
    if (!aiStatus) return;
    aiStatus.textContent = message;
    aiStatus.className = `settings-save-status ${kind}`.trim();
  }
  function setEngineerStatus(message, kind = '') {
    if (!engineerStatus) return;
    engineerStatus.textContent = message;
    engineerStatus.className = `settings-save-status ${kind}`.trim();
  }
  function setHunterStatus(message, kind = '') {
    if (!hunterStatus) return;
    hunterStatus.textContent = message;
    hunterStatus.className = `settings-save-status ${kind}`.trim();
  }
  function setIntelStatus(message, kind = '') {
    if (!intelStatus) return;
    intelStatus.textContent = message;
    intelStatus.className = `settings-save-status ${kind}`.trim();
  }
  function setIncidentStatus(message, kind = '') {
    if (!incidentStatus) return;
    incidentStatus.textContent = message;
    incidentStatus.className = `settings-save-status ${kind}`.trim();
  }
  function currentAiSettings() {
    return {
      mode: aiMode?.value || 'ollama',
      ollama_model: ollamaModel?.value.trim() || 'devstral:latest',
      ollama_url: ollamaUrl?.value.trim() || 'http://127.0.0.1:11434',
      cloud_provider: cloudProvider?.value.trim() || 'gpt-cli',
      cloud_model: cloudModel?.value.trim() || '',
      cloud_command: cloudCommand?.value.trim() || '',
      hybrid_policy: hybridPolicy?.value || 'cloud_for_critical_high_or_recommended'
    };
  }
  function applyAiSettings(settings) {
    if (!settings) return;
    if (aiMode) aiMode.value = settings.mode || 'ollama';
    if (ollamaModel) {
      const selected = settings.ollama_model || 'devstral:latest';
      if (![...ollamaModel.options].some(option => option.value === selected)) {
        ollamaModel.add(new Option(selected, selected, true, true));
      }
      ollamaModel.value = selected;
      ollamaModel.dataset.selectedModel = selected;
    }
    if (ollamaUrl) ollamaUrl.value = settings.ollama_url || 'http://127.0.0.1:11434';
    if (cloudProvider) cloudProvider.value = settings.cloud_provider || 'gpt-cli';
    if (cloudModel) cloudModel.value = settings.cloud_model || '';
    if (cloudCommand) cloudCommand.value = settings.cloud_command || '';
    if (hybridPolicy) hybridPolicy.value = settings.hybrid_policy || 'cloud_for_critical_high_or_recommended';
  }
  async function refreshAiSettings() {
    if (!saveAiButton) return;
    try {
      const response = await fetch('/api/soc-settings/ai-model', {cache: 'no-store'});
      const data = await response.json();
      if (data.ok && data.settings) applyAiSettings(data.settings);
    } catch (_) {
      setAiStatus('Could not refresh model settings from the portal API.', 'error');
    }
  }
  async function refreshOllamaModels() {
    if (!ollamaModel) return;
    const selected = ollamaModel.value || ollamaModel.dataset.selectedModel || 'devstral:latest';
    try {
      const response = await fetch('/api/soc-settings/ollama-models', {cache: 'no-store'});
      const data = await response.json();
      if (!data.ok || !Array.isArray(data.models)) return;
      const models = data.models.length ? data.models : [selected];
      ollamaModel.innerHTML = '';
      models.forEach(model => ollamaModel.add(new Option(model, model, false, model === selected)));
      if (![...ollamaModel.options].some(option => option.value === selected)) {
        ollamaModel.add(new Option(selected, selected, true, true));
      }
      ollamaModel.value = selected;
    } catch (_) {
      setAiStatus('Could not refresh Ollama model list from ollama ls.', 'error');
    }
  }
  async function saveAiSettings() {
    if (!saveAiButton) return;
    const payload = currentAiSettings();
    if ((payload.mode === 'cloud' || payload.mode === 'hybrid') && !payload.cloud_command) {
      setAiStatus('Cloud or hybrid mode requires a cloud CLI command.', 'error');
      return;
    }
    saveAiButton.disabled = true;
    setAiStatus('Saving...');
    try {
      const response = await fetch('/api/soc-settings/ai-model', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) {
        throw new Error(data.error || `Save failed with HTTP ${response.status}`);
      }
      applyAiSettings(data.settings);
      setAiStatus('Saved. New AI analyses will use this model routing.', 'ok');
    } catch (error) {
      setAiStatus(String(error.message || error), 'error');
    } finally {
      saveAiButton.disabled = false;
    }
  }
  async function refreshPrompt() {
    if (!editor) return;
    try {
      const response = await fetch('/api/soc-settings/analyst-prompt', {cache: 'no-store'});
      const data = await response.json();
      if (data.ok && typeof data.prompt === 'string') {
        editor.value = data.prompt.trimEnd();
      }
    } catch (_) {
      setStatus('Could not refresh prompt from the portal API.', 'error');
    }
  }
  async function refreshEngineerPrompt() {
    if (!engineerEditor) return;
    try {
      const response = await fetch('/api/soc-settings/siem-engineer-prompt', {cache: 'no-store'});
      const data = await response.json();
      if (data.ok && typeof data.prompt === 'string') {
        engineerEditor.value = data.prompt.trimEnd();
      }
    } catch (_) {
      setEngineerStatus('Could not refresh prompt from the portal API.', 'error');
    }
  }
  async function refreshHunterPrompt() {
    if (!hunterEditor) return;
    try {
      const response = await fetch('/api/soc-settings/threat-hunter-prompt', {cache: 'no-store'});
      const data = await response.json();
      if (data.ok && typeof data.prompt === 'string') {
        hunterEditor.value = data.prompt.trimEnd();
      }
    } catch (_) {
      setHunterStatus('Could not refresh prompt from the portal API.', 'error');
    }
  }
  async function refreshIntelPrompt() {
    if (!intelEditor) return;
    try {
      const response = await fetch('/api/soc-settings/cyber-threat-intel-prompt', {cache: 'no-store'});
      const data = await response.json();
      if (data.ok && typeof data.prompt === 'string') {
        intelEditor.value = data.prompt.trimEnd();
      }
    } catch (_) {
      setIntelStatus('Could not refresh prompt from the portal API.', 'error');
    }
  }
  async function refreshIncidentPrompt() {
    if (!incidentEditor) return;
    try {
      const response = await fetch('/api/soc-settings/incident-responder-prompt', {cache: 'no-store'});
      const data = await response.json();
      if (data.ok && typeof data.prompt === 'string') {
        incidentEditor.value = data.prompt.trimEnd();
      }
    } catch (_) {
      setIncidentStatus('Could not refresh prompt from the portal API.', 'error');
    }
  }
  async function savePrompt() {
    if (!editor || !saveButton) return;
    const prompt = editor.value.trim();
    if (!prompt) {
      setStatus('Prompt cannot be empty.', 'error');
      return;
    }
    saveButton.disabled = true;
    setStatus('Saving...');
    try {
      const response = await fetch('/api/soc-settings/analyst-prompt', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({prompt})
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) {
        throw new Error(data.error || `Save failed with HTTP ${response.status}`);
      }
      setStatus('Saved. New AI analyses will use this prompt.', 'ok');
    } catch (error) {
      setStatus(String(error.message || error), 'error');
    } finally {
      saveButton.disabled = false;
    }
  }
  async function saveEngineerPrompt() {
    if (!engineerEditor || !saveEngineerButton) return;
    const prompt = engineerEditor.value.trim();
    if (!prompt) {
      setEngineerStatus('Prompt cannot be empty.', 'error');
      return;
    }
    saveEngineerButton.disabled = true;
    setEngineerStatus('Saving...');
    try {
      const response = await fetch('/api/soc-settings/siem-engineer-prompt', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({prompt})
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) {
        throw new Error(data.error || `Save failed with HTTP ${response.status}`);
      }
      setEngineerStatus('Saved. New SIEM Engineering reviews will use this prompt.', 'ok');
    } catch (error) {
      setEngineerStatus(String(error.message || error), 'error');
    } finally {
      saveEngineerButton.disabled = false;
    }
  }
  async function saveHunterPrompt() {
    if (!hunterEditor || !saveHunterButton) return;
    const prompt = hunterEditor.value.trim();
    if (!prompt) {
      setHunterStatus('Prompt cannot be empty.', 'error');
      return;
    }
    saveHunterButton.disabled = true;
    setHunterStatus('Saving...');
    try {
      const response = await fetch('/api/soc-settings/threat-hunter-prompt', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({prompt})
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) {
        throw new Error(data.error || `Save failed with HTTP ${response.status}`);
      }
      setHunterStatus('Saved. New Threat Hunter recommendations will use this prompt.', 'ok');
    } catch (error) {
      setHunterStatus(String(error.message || error), 'error');
    } finally {
      saveHunterButton.disabled = false;
    }
  }
  async function saveIntelPrompt() {
    if (!intelEditor || !saveIntelButton) return;
    const prompt = intelEditor.value.trim();
    if (!prompt) {
      setIntelStatus('Prompt cannot be empty.', 'error');
      return;
    }
    saveIntelButton.disabled = true;
    setIntelStatus('Saving...');
    try {
      const response = await fetch('/api/soc-settings/cyber-threat-intel-prompt', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({prompt})
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) {
        throw new Error(data.error || `Save failed with HTTP ${response.status}`);
      }
      setIntelStatus('Saved. New Cyber Threat Intel briefs will use this prompt.', 'ok');
    } catch (error) {
      setIntelStatus(String(error.message || error), 'error');
    } finally {
      saveIntelButton.disabled = false;
    }
  }
  async function saveIncidentPrompt() {
    if (!incidentEditor || !saveIncidentButton) return;
    const prompt = incidentEditor.value.trim();
    if (!prompt) {
      setIncidentStatus('Prompt cannot be empty.', 'error');
      return;
    }
    saveIncidentButton.disabled = true;
    setIncidentStatus('Saving...');
    try {
      const response = await fetch('/api/soc-settings/incident-responder-prompt', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({prompt})
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) {
        throw new Error(data.error || `Save failed with HTTP ${response.status}`);
      }
      setIncidentStatus('Saved. New Incident Responder guidance will use this prompt.', 'ok');
    } catch (error) {
      setIncidentStatus(String(error.message || error), 'error');
    } finally {
      saveIncidentButton.disabled = false;
    }
  }
  saveAiButton?.addEventListener('click', saveAiSettings);
  saveButton?.addEventListener('click', savePrompt);
  saveEngineerButton?.addEventListener('click', saveEngineerPrompt);
  saveHunterButton?.addEventListener('click', saveHunterPrompt);
  saveIntelButton?.addEventListener('click', saveIntelPrompt);
  saveIncidentButton?.addEventListener('click', saveIncidentPrompt);
  refreshAiSettings().then(refreshOllamaModels);
  if (ollamaModel) {
    setInterval(refreshOllamaModels, 60000);
  }
  refreshPrompt();
  refreshEngineerPrompt();
  refreshHunterPrompt();
  refreshIntelPrompt();
  refreshIncidentPrompt();
})();
</script>
'''


def inject_settings_assets(text: str) -> str:
    if SETTINGS_PAGE_CSS not in text:
        text = text.replace('</head>', SETTINGS_PAGE_CSS + '</head>', 1)
    if SETTINGS_PAGE_JS not in text:
        text = text.replace('</body>', SETTINGS_PAGE_JS + '</body>', 1)
    return text


def inject_executive_home_assets(text: str) -> str:
    if EXECUTIVE_HOME_CSS not in text:
        text = text.replace('</head>', EXECUTIVE_HOME_CSS + '</head>', 1)
    return text


SIEM_ENGINEERING_CSS = '''
<style>
.siem-engineering-view{display:grid;gap:14px;padding-top:8px}.siem-eng-hero{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:18px;align-items:end;border-bottom:1px solid rgba(148,163,184,.12);padding:4px 0 16px}.siem-eng-hero h2{margin:8px 0 5px;color:#f5f9ff;font-size:26px;line-height:1;letter-spacing:-.02em}.siem-eng-hero p{margin:0;color:#9aaabd;font-size:13px;line-height:1.4}.settings-kicker{display:inline-block;color:#8ff4ff;font-size:10.5px;font-weight:950;text-transform:uppercase;letter-spacing:.13em}.siem-model-card{min-width:250px;text-align:right}.siem-model-card span,.siem-eng-kpis span{display:block;color:#8ff4ff;font-size:10px;font-weight:950;text-transform:uppercase;letter-spacing:.1em}.siem-model-card strong{display:block;margin-top:6px;color:#f3f8ff;font-size:16px}.siem-model-card em{display:block;margin-top:4px;color:#91a4ba;font-size:12px;font-style:normal}.siem-eng-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.siem-eng-kpis article{border:1px solid rgba(148,163,184,.10);border-radius:8px;padding:10px 12px;background:#0b141d}.siem-eng-kpis strong{display:block;margin-top:6px;color:#f7fbff;font-size:18px;line-height:1}.siem-eng-kpis em{display:block;margin-top:5px;color:#91a4ba;font-size:11.5px;font-style:normal}.siem-roi-card{display:grid;gap:12px;border:1px solid rgba(34,211,238,.16);border-radius:8px;padding:14px;background:#0d1620}.siem-roi-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px}.siem-roi-head h3{margin:6px 0 0;color:#f5f9ff;font-size:18px;line-height:1.2;letter-spacing:-.01em}.siem-roi-head code{display:block;margin-top:6px;color:#91a4ba;background:transparent;font:11.5px/1.35 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;white-space:normal;overflow-wrap:anywhere}.siem-roi-rank{min-width:94px;text-align:right}.siem-roi-rank span{display:block;color:#8ff4ff;font-size:10px;font-weight:950;text-transform:uppercase;letter-spacing:.1em}.siem-roi-rank strong{display:block;margin-top:6px;font-size:17px;line-height:1;text-transform:capitalize}.siem-roi-table{width:100%;border-collapse:collapse}.siem-roi-table th{width:84px;padding:9px 10px 9px 0;border-top:1px solid rgba(148,163,184,.10);color:#8ff4ff;font-size:10px;font-weight:950;text-align:left;text-transform:uppercase;letter-spacing:.1em;vertical-align:top}.siem-roi-table td{padding:9px 0;border-top:1px solid rgba(148,163,184,.10);color:#dce8f7;font-size:13px;line-height:1.42;vertical-align:top;overflow-wrap:anywhere}.siem-table-section{display:grid;gap:8px}.siem-table-title{padding:0 2px}.siem-table-title h3{margin:0;color:#f4f8ff;font-size:16px;letter-spacing:-.01em}.siem-table-title p{display:none}.siem-table-wrap{overflow:auto;border:1px solid rgba(148,163,184,.11);border-radius:8px;background:#0d1620}.siem-engineering-table{width:100%;min-width:1040px;border-collapse:collapse}.siem-engineering-table th{padding:9px 11px;border-bottom:1px solid rgba(148,163,184,.12);color:#96a6b8;background:#101b26;font-size:10px;font-weight:900;text-align:left;text-transform:uppercase;letter-spacing:.08em}.siem-engineering-table td{padding:11px;border-bottom:1px solid rgba(148,163,184,.09);vertical-align:top;color:#d7e3f1;font-size:12.5px;line-height:1.36}.siem-engineering-table tbody tr{height:86px}.siem-engineering-table tbody tr:hover{background:rgba(34,211,238,.03)}.siem-engineering-table td:nth-child(1){width:108px}.siem-engineering-table td:nth-child(2){width:260px}.siem-engineering-table td:nth-child(3){width:116px}.siem-engineering-table td:nth-child(5){width:116px}.siem-engineering-table strong{display:block;color:#f4f8ff;font-size:12.5px;line-height:1.25}.siem-engineering-table code{display:block;margin-top:6px;color:#91a4ba;background:transparent;font:11px/1.3 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;white-space:normal;overflow-wrap:anywhere}.siem-table-pill{display:inline-flex;align-items:center;border:1px solid rgba(34,211,238,.16);border-radius:999px;padding:3px 7px;color:#8ff4ff;background:rgba(34,211,238,.035);font-size:10px;font-weight:900;text-transform:uppercase;letter-spacing:.04em}.siem-reason-cell{min-width:380px}.siem-reason-cell p{margin:0;color:#dce8f7;font-size:12.5px;line-height:1.42;overflow-wrap:anywhere}.siem-reason-cell em{display:block;margin-top:5px;color:#9fb0c4;font-size:12px;font-style:normal;line-height:1.35;overflow-wrap:anywhere}.siem-engineering-table td:last-child b{display:block;color:#f4f8ff;font-size:17px;line-height:1}.siem-engineering-table td:last-child span{display:block;margin-top:5px;color:#91a4ba;font-size:11px;line-height:1.3;overflow-wrap:anywhere}.siem-empty-row td{padding:18px 12px;color:#91a4ba;text-align:center}@media(max-width:1100px){.siem-eng-hero{grid-template-columns:1fr}.siem-model-card{text-align:left}.siem-eng-kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.siem-table-title{display:grid}}@media(max-width:680px){.siem-eng-kpis{grid-template-columns:1fr}.siem-roi-head{display:grid}.siem-roi-rank{text-align:left}.siem-roi-table th{width:70px}}
</style>
'''


def inject_siem_engineering_assets(text: str) -> str:
    if SIEM_ENGINEERING_CSS not in text:
        text = text.replace('</head>', SIEM_ENGINEERING_CSS + '</head>', 1)
    return text


THREAT_HUNTER_CSS = '''
<style>
.threat-hunter-view{display:grid;gap:16px;padding-top:12px}.threat-hunter-hero{border:1px solid rgba(148,163,184,.12);border-radius:10px;padding:18px;background:#0d1620;box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}.threat-hunter-hero h2{margin:10px 0 7px;color:#f5f9ff;font-size:28px;line-height:1;letter-spacing:-.025em}.threat-hunter-hero p{max-width:82ch;margin:0;color:#9aaabd;font-size:13px;line-height:1.55}.threat-hunt-row{cursor:pointer}.threat-hunt-row[aria-expanded="true"]{background:rgba(34,211,238,.07);box-shadow:inset 3px 0 0 #22d3ee}.threat-hunt-table .hunt-hypothesis{min-width:420px;color:#dce8f7;line-height:1.52}.threat-hunt-table td:last-child b{display:block;color:#f4f8ff;font-size:18px;line-height:1}.threat-hunt-table td:last-child span{display:block;margin-top:7px;color:#91a4ba;font-size:11.5px;line-height:1.35}.threat-hunt-detail td{padding:0;border-bottom:1px solid rgba(34,211,238,.14);background:#08111a}.hunt-detail-panel{display:grid;grid-template-columns:minmax(260px,.42fr) minmax(420px,1fr);gap:16px;padding:16px}.hunt-detail-copy{border:1px solid rgba(148,163,184,.12);border-radius:10px;padding:14px;background:#0d1620}.hunt-detail-copy h3{margin:0 0 8px;color:#f4f8ff;font-size:16px}.hunt-detail-copy p{margin:0 0 12px;color:#9aa8b8;font-size:13px;line-height:1.5}.hunt-detail-copy dl{display:grid;gap:8px;margin:0}.hunt-detail-copy div{border-top:1px solid rgba(148,163,184,.09);padding-top:8px}.hunt-detail-copy dt{color:#8ff4ff;font-size:10.5px;font-weight:950;text-transform:uppercase;letter-spacing:.08em}.hunt-detail-copy dd{margin:4px 0 0;color:#d7e3f1;font-size:12.5px;line-height:1.4;overflow-wrap:anywhere}.hunt-query-grid{display:grid;gap:12px}.hunt-code-card{border:1px solid rgba(148,163,184,.12);border-radius:10px;overflow:hidden;background:#071018}.hunt-code-card header{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 12px;border-bottom:1px solid rgba(148,163,184,.10);background:#101b26}.hunt-code-card header span{color:#8ff4ff;font-size:11px;font-weight:950;text-transform:uppercase;letter-spacing:.08em}.hunt-code-card button{border:1px solid rgba(34,211,238,.28);border-radius:8px;padding:6px 9px;color:#8ff4ff;background:rgba(34,211,238,.06);font-size:11px;font-weight:900;cursor:pointer}.hunt-code-card button:hover{border-color:rgba(143,244,255,.72);color:#f5fdff}.hunt-code-card pre{margin:0;max-height:260px;overflow:auto;padding:13px;color:#dce9f8;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;white-space:pre}@media(max-width:900px){.hunt-detail-panel{grid-template-columns:1fr}.threat-hunt-table .hunt-hypothesis{min-width:320px}}
</style>
'''


THREAT_HUNTER_JS = '''
<script>
(() => {
  document.querySelectorAll('[data-hunt-toggle]').forEach(row => {
    row.addEventListener('click', event => {
      if (event.target.closest('button')) return;
      const detail = row.parentElement?.querySelector('.threat-hunt-detail');
      const expanded = row.getAttribute('aria-expanded') === 'true';
      row.setAttribute('aria-expanded', String(!expanded));
      if (detail) detail.hidden = expanded;
    });
    row.addEventListener('keydown', event => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      event.preventDefault();
      row.click();
    });
  });
  document.querySelectorAll('[data-copy-target]').forEach(button => {
    button.addEventListener('click', async event => {
      event.preventDefault();
      event.stopPropagation();
      const target = document.getElementById(button.dataset.copyTarget || '');
      const text = target?.textContent || '';
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
        const original = button.textContent;
        button.textContent = 'Copied';
        window.setTimeout(() => { button.textContent = original; }, 1200);
      } catch (_) {
        button.textContent = 'Copy failed';
        window.setTimeout(() => { button.textContent = 'Copy'; }, 1200);
      }
    });
  });
})();
</script>
'''


def inject_threat_hunter_assets(text: str) -> str:
    text = inject_siem_engineering_assets(text)
    if THREAT_HUNTER_CSS not in text:
        text = text.replace('</head>', THREAT_HUNTER_CSS + '</head>', 1)
    if THREAT_HUNTER_JS not in text:
        text = text.replace('</body>', THREAT_HUNTER_JS + '</body>', 1)
    return text


SYSTEM_HEALTH_CSS = '''
<style>
.system-health-link{display:block;text-decoration:none}.system-health-view{display:grid;gap:14px;padding-top:8px}.system-health-hero{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:18px;align-items:end;border-bottom:1px solid rgba(148,163,184,.12);padding:4px 0 16px}.system-health-hero h2{margin:8px 0 5px;color:#f5f9ff;font-size:26px;line-height:1;letter-spacing:-.02em}.system-health-hero p{max-width:82ch;margin:0;color:#9aaabd;font-size:13px;line-height:1.45}.system-health-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.system-health-kpis article,.system-health-panel{border:1px solid rgba(148,163,184,.11);border-radius:8px;background:#0d1620}.system-health-kpis article{padding:11px 12px}.system-health-kpis span{display:block;color:#8ff4ff;font-size:10px;font-weight:950;text-transform:uppercase;letter-spacing:.1em}.system-health-kpis strong{display:block;margin-top:7px;color:#f7fbff;font-size:18px;line-height:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.system-health-kpis em{display:block;margin-top:6px;color:#91a4ba;font-size:11.5px;font-style:normal;line-height:1.35}.system-health-panel{overflow:hidden}.system-health-panel-title{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 14px;border-bottom:1px solid rgba(148,163,184,.10);background:#101b26}.system-health-panel-title h3{margin:0;color:#f4f8ff;font-size:16px;letter-spacing:-.01em}.system-health-panel-title span{color:#91a4ba;font-size:12px}.health-gap-list{display:grid;gap:8px;padding:12px}.health-gap-item{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;border:1px solid rgba(246,199,109,.22);border-radius:8px;padding:9px 10px;background:rgba(246,199,109,.055);color:#dce8f7;font-size:12px}.health-gap-item b{color:#f6c76d}.health-gap-item code{color:#f3f8ff;background:transparent;font:11.5px/1.35 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace}.health-gap-empty{padding:12px;color:#91a4ba;font-size:12px}.system-health-table-wrap{overflow:auto}.system-health-table{width:100%;min-width:980px;border-collapse:collapse}.system-health-table th{padding:9px 11px;border-bottom:1px solid rgba(148,163,184,.12);color:#96a6b8;background:#101b26;font-size:10px;font-weight:900;text-align:left;text-transform:uppercase;letter-spacing:.08em}.system-health-table td{padding:11px;border-bottom:1px solid rgba(148,163,184,.09);vertical-align:top;color:#d7e3f1;font-size:12.5px;line-height:1.35}.system-health-table code{color:#dce9f8;background:rgba(148,163,184,.05);border:1px solid rgba(148,163,184,.12);border-radius:6px;padding:3px 6px;font-size:11.5px;white-space:nowrap}.health-result{display:inline-flex;align-items:center;border:1px solid rgba(34,197,94,.24);border-radius:999px;padding:3px 8px;color:#86efac;background:rgba(34,197,94,.055);font-size:10.5px;font-weight:950;text-transform:uppercase;letter-spacing:.04em}.health-result.failed{border-color:rgba(251,113,133,.34);color:#fb7185;background:rgba(251,113,133,.075)}.health-row-failed{background:rgba(251,113,133,.045)}.health-row-failed td{border-bottom-color:rgba(251,113,133,.16)}@media(max-width:900px){.system-health-kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.system-health-hero{grid-template-columns:1fr}}@media(max-width:620px){.system-health-kpis{grid-template-columns:1fr}.health-gap-item{grid-template-columns:1fr}}
</style>
'''


SYSTEM_HEALTH_JS = '''
<script>
(() => {
  const refreshButton = document.querySelector('#system-health-refresh');
  const latest = document.querySelector('#health-latest');
  const latestDetail = document.querySelector('#health-latest-detail');
  const successful = document.querySelector('#health-successful');
  const unsuccessful = document.querySelector('#health-unsuccessful');
  const gaps = document.querySelector('#health-gaps');
  const gapList = document.querySelector('#health-gap-list');
  const gapNote = document.querySelector('#health-gap-note');
  const rows = document.querySelector('#health-beacon-rows');
  const eventNote = document.querySelector('#health-event-note');
  const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  const fmt = value => typeof formatProjectIso === 'function' ? formatProjectIso(value) : String(value || '');
  function detailText(entry) {
    if (entry.error) return entry.error;
    if (entry.rule_name) return entry.rule_name;
    if (entry.message_type === 'relay_heartbeat') return 'relay heartbeat';
    if (entry.message_type === 'relay_health_recovery') return 'relay recovery';
    return 'beacon';
  }
  function renderGaps(items) {
    if (!gapList) return;
    if (!items.length) {
      gapList.innerHTML = '<div class="health-gap-empty">No successful-beacon gaps over 10 minutes in this window.</div>';
      return;
    }
    gapList.innerHTML = items.map(gap => `
      <div class="health-gap-item">
        <b>${esc(gap.minutes)} min</b>
        <code>${esc(fmt(gap.start))} -> ${esc(fmt(gap.end))}</code>
        <span>${esc(gap.status || 'closed')}</span>
      </div>`).join('');
  }
  function renderRows(entries) {
    if (!rows) return;
    if (!entries.length) {
      rows.innerHTML = '<tr><td colspan="7">No beacon history found in the last 24 hours.</td></tr>';
      return;
    }
    rows.innerHTML = [...entries].reverse().map(entry => {
      const failed = !entry.successful;
      return `<tr class="${failed ? 'health-row-failed' : ''}">
        <td><code>${esc(fmt(entry.timestamp))}</code></td>
        <td><span class="health-result ${failed ? 'failed' : ''}">${failed ? 'Unsuccessful' : 'Success'}</span></td>
        <td>${esc(entry.stage || 'unknown')}</td>
        <td>${esc(entry.relay_host || 'n8n')}</td>
        <td>${esc(entry.alert_count ?? entry.posted_webhook_alerts ?? 'n/a')}</td>
        <td>${entry.http_status ? `<code>${esc(entry.http_status)}</code>` : '<span>n/a</span>'}</td>
        <td>${esc(detailText(entry))}</td>
      </tr>`;
    }).join('');
  }
  async function loadHealth() {
    refreshButton?.setAttribute('aria-busy', 'true');
    refreshButton?.classList.add('refreshing');
    try {
      const response = await fetch('/api/system-health/beacons?hours=24&ts=' + Date.now(), {cache: 'no-store'});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      const summary = data.summary || {};
      if (latest) latest.textContent = summary.latest ? fmt(summary.latest.timestamp) : 'No beacons';
      if (latestDetail) latestDetail.textContent = summary.latest ? detailText(summary.latest) : 'No beacon history found.';
      if (successful) successful.textContent = String(summary.successful || 0);
      if (unsuccessful) unsuccessful.textContent = String(summary.unsuccessful || 0);
      if (gaps) gaps.textContent = String(summary.gap_count || 0);
      if (gapNote) gapNote.textContent = summary.gap_count ? `${summary.gap_count} gap(s) require review` : 'No gaps over 10 minutes';
      if (eventNote) eventNote.textContent = `${summary.total || 0} event(s), generated ${fmt(data.generated_at)}`;
      renderGaps(data.gaps || []);
      renderRows(data.entries || []);
    } catch (error) {
      if (latest) latest.textContent = 'Unavailable';
      if (latestDetail) latestDetail.textContent = String(error.message || error);
      if (rows) rows.innerHTML = `<tr><td colspan="7">System Health API failed: ${esc(error.message || error)}</td></tr>`;
    } finally {
      refreshButton?.setAttribute('aria-busy', 'false');
      refreshButton?.classList.remove('refreshing');
    }
  }
  refreshButton?.addEventListener('click', loadHealth);
  loadHealth();
  setInterval(loadHealth, 60000);
})();
</script>
'''


def inject_system_health_assets(text: str) -> str:
    if SYSTEM_HEALTH_CSS not in text:
        text = text.replace('</head>', SYSTEM_HEALTH_CSS + '</head>', 1)
    if SYSTEM_HEALTH_JS not in text:
        text = text.replace('</body>', SYSTEM_HEALTH_JS + '</body>', 1)
    return text


FLOW_PAGE_CSS = '''
<style>
.flow-page-view{display:block}
.flow-product-hero{position:relative;display:grid;grid-template-columns:minmax(260px,.34fr) minmax(760px,1fr);gap:22px;align-items:start;border:1px solid rgba(148,163,184,.14);border-radius:16px;padding:24px;background:linear-gradient(135deg,#0c151f 0%,#101923 58%,#071018 100%);box-shadow:0 22px 48px rgba(0,0,0,.24),inset 0 1px 0 rgba(255,255,255,.035)}
.flow-privacy-toggle{position:absolute;right:18px;top:18px;z-index:10;width:46px;height:46px;display:grid;place-items:center;border:1px solid rgba(34,211,238,.32);border-radius:15px;padding:0;background:rgba(7,16,24,.82);box-shadow:0 14px 30px rgba(0,0,0,.28),0 0 18px rgba(34,211,238,.10),inset 0 1px 0 rgba(255,255,255,.04);cursor:pointer;transition:transform .16s ease,border-color .16s ease,box-shadow .16s ease}
.flow-privacy-toggle:hover{transform:translateY(-1px);border-color:rgba(143,244,255,.72);box-shadow:0 18px 38px rgba(0,0,0,.34),0 0 24px rgba(34,211,238,.22),inset 0 1px 0 rgba(255,255,255,.06)}
.flow-privacy-toggle[aria-pressed="true"]{border-color:rgba(143,244,255,.88);box-shadow:0 18px 38px rgba(0,0,0,.34),0 0 30px rgba(34,211,238,.30),inset 0 0 18px rgba(34,211,238,.07)}
.flow-privacy-toggle img{width:38px;height:38px;display:block;border-radius:12px;object-fit:cover;filter:drop-shadow(0 0 8px rgba(34,211,238,.18))}
.flow-product-copy{position:sticky;top:18px;display:flex;flex-direction:column;justify-content:center;min-width:0;padding:8px 2px 0}
.flow-product-copy h2{max-width:18ch;margin:8px 0 10px;color:#f5f9ff;font-size:24px;line-height:1.08;letter-spacing:-.025em}
.flow-product-copy p{max-width:50ch;margin:18px 0 0;color:#aab8ca;font-size:14px;line-height:1.62}
.flow-pulse-divider{width:100%;height:2px;margin-top:14px;border-radius:999px;background:linear-gradient(90deg,rgba(34,211,238,.14),rgba(143,244,255,.78),rgba(34,211,238,.14));box-shadow:0 0 10px rgba(34,211,238,.16);animation:flow-divider-pulse 2.8s ease-in-out infinite}
.flow-product-map{display:grid;gap:16px;min-width:0;border:1px solid rgba(34,211,238,.13);border-radius:14px;padding:18px;background:radial-gradient(circle at 78% 18%,rgba(34,211,238,.08),transparent 34%),linear-gradient(180deg,rgba(7,16,24,.62),rgba(6,12,20,.90))}
.flow-lane{display:grid;grid-template-columns:minmax(150px,1fr) minmax(84px,.28fr) minmax(150px,1fr) minmax(84px,.28fr) minmax(150px,1fr) minmax(84px,.28fr) minmax(150px,1fr);gap:10px;align-items:center;min-width:0}
.flow-lane-outputs{grid-template-columns:repeat(6,minmax(128px,1fr))}
.flow-system-node{position:relative;display:grid;grid-template-rows:auto 1fr auto;gap:10px;min-width:0;min-height:150px;border:1px solid rgba(148,163,184,.15);border-radius:14px;padding:14px;background:rgba(10,18,27,.92);box-shadow:0 16px 38px rgba(0,0,0,.24),inset 0 1px 0 rgba(255,255,255,.035);transition:transform .16s ease,border-color .16s ease,box-shadow .16s ease}
.flow-system-node:hover{transform:translateY(-2px);border-color:rgba(34,211,238,.32);box-shadow:0 20px 44px rgba(0,0,0,.30),0 0 24px rgba(34,211,238,.10),inset 0 1px 0 rgba(255,255,255,.045)}
.flow-logo-ring{width:52px;height:52px;display:grid;place-items:center;overflow:hidden;border:1px solid rgba(148,163,184,.16);border-radius:15px;background:rgba(255,255,255,.035);box-shadow:inset 0 0 20px rgba(34,211,238,.035)}
.flow-logo-ring img{width:36px;height:36px;margin:auto;object-fit:contain;object-position:center;display:block;filter:drop-shadow(0 0 8px rgba(34,211,238,.16))}
.flow-logo-ring img[alt="Security Onion logo"]{width:40px;height:40px}
.flow-logo-ring img[alt="Raspberry Pi logo"]{width:38px;height:38px}
.flow-logo-ring img[alt="Docker logo"],.flow-logo-ring img[alt="n8n logo"],.flow-logo-ring img[alt="SQLite logo"],.flow-logo-ring img[alt="Telegram logo"]{width:38px;height:38px}
.flow-logo-ring img[alt="Apple logo"]{width:34px;height:34px}
.flow-logo-ring img[alt="Ollama logo"]{width:34px;height:38px}
.flow-logo-ring img[alt="Onion Sentinel logo"]{width:44px;height:44px}
.flow-logo-ring span{color:#8ff4ff;font-size:13px;font-weight:950;letter-spacing:.06em}
.flow-logo-pair{display:flex;align-items:center;gap:8px;margin:0}
.flow-logo-pair .flow-logo-ring{margin:0!important}
.flow-system-node strong{display:block;color:#f4f8ff;font-size:15px;line-height:1.22}
.flow-system-node span:not(.flow-logo-ring):not(.flow-logo-ring span){display:block;margin-top:6px;color:#91a4ba;font-size:12px;line-height:1.35;overflow-wrap:anywhere}
.flow-ip-address{font-variant-numeric:tabular-nums;letter-spacing:.02em;color:#7f8fa3!important}
.flow-ip-address.visible{color:#91a4ba!important}
.flow-system-node em{align-self:end;color:#8ff4ff;font-size:10px;font-style:normal;font-weight:900;text-transform:uppercase;letter-spacing:.08em;line-height:1.2}
.flow-connector{--connector-y:48px;position:relative;display:grid;align-items:start;justify-items:center;min-width:56px;height:70px;background:linear-gradient(90deg,rgba(34,211,238,.16),rgba(143,244,255,.82),rgba(34,211,238,.16)) center var(--connector-y)/100% 2px no-repeat}
.flow-connector:before{content:"";position:absolute;left:0;top:var(--connector-y);width:8px;height:8px;border-radius:999px;background:#8ff4ff;box-shadow:0 0 0 4px rgba(34,211,238,.10),0 0 18px rgba(34,211,238,.75);transform:translate(-50%,-50%);animation:flow-dot-horizontal 3.6s linear infinite}
.flow-connector:after{content:"";position:absolute;right:-2px;top:var(--connector-y);width:9px;height:9px;border-top:2px solid #8ff4ff;border-right:2px solid #8ff4ff;transform:translateY(-50%) rotate(45deg)}
.flow-connector span{position:relative;z-index:1;max-width:100%;white-space:normal;text-align:center;line-height:1.12;border:1px solid rgba(143,244,255,.22);border-radius:999px;padding:6px 8px;color:#dce9f8;background:rgba(7,16,24,.96);font-size:9.5px;font-weight:850;box-shadow:0 0 0 6px rgba(7,16,24,.78),0 0 16px rgba(0,0,0,.30)}
.flow-downlink{position:relative;display:grid;align-items:center;justify-items:center;min-height:58px}
.flow-downlink:before{content:"";position:absolute;top:0;bottom:0;left:50%;width:2px;background:linear-gradient(180deg,rgba(143,244,255,.82),rgba(34,211,238,.12));transform:translateX(-50%)}
.flow-downlink:after{content:"";position:absolute;bottom:2px;left:50%;width:9px;height:9px;border-right:2px solid #8ff4ff;border-bottom:2px solid #8ff4ff;transform:translateX(-50%) rotate(45deg)}
.flow-downlink span{position:relative;z-index:1;justify-self:end;width:max-content;max-width:min(520px,calc(50% - 28px));margin-right:calc(50% + 22px);border:1px solid rgba(143,244,255,.22);border-radius:999px;padding:7px 13px;color:#dce9f8;background:rgba(7,16,24,.96);font-size:10.5px;font-weight:850;text-align:center;line-height:1.2;box-shadow:0 0 0 6px rgba(7,16,24,.78)}
.flow-enrichment-band{display:grid;grid-template-columns:minmax(230px,.28fr) minmax(520px,1fr);gap:14px;align-items:stretch;min-width:0;border:1px solid rgba(34,211,238,.16);border-radius:14px;padding:14px;background:rgba(34,211,238,.035);box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}
.flow-enrichment-core{border-color:rgba(34,211,238,.34);box-shadow:0 16px 38px rgba(0,0,0,.22),0 0 26px rgba(34,211,238,.07),inset 0 1px 0 rgba(255,255,255,.04)}
.enrichment-service-grid{display:grid;grid-template-columns:repeat(4,minmax(126px,1fr));gap:8px;min-width:0}
.enrichment-service{display:grid;grid-template-columns:34px minmax(0,1fr);grid-template-rows:auto auto;gap:7px 9px;align-items:center;min-width:0;border:1px solid rgba(148,163,184,.13);border-radius:11px;padding:9px;background:rgba(7,16,24,.72);box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}
.enrichment-logo{grid-row:1 / 3;align-self:center;width:34px;height:34px;display:grid;place-items:center;overflow:hidden;border:1px solid rgba(34,211,238,.14);border-radius:10px;background:rgba(255,255,255,.035)}
.enrichment-logo img{width:23px;height:23px;margin:auto;object-fit:contain;object-position:center;display:block;filter:drop-shadow(0 0 6px rgba(34,211,238,.14))}
.enrichment-logo img[alt="Google Safe Browsing logo"],.enrichment-logo img[alt="urlscan.io logo"],.enrichment-logo img[alt="VirusTotal logo"]{width:24px;height:24px}
.enrichment-logo img[alt="CISA KEV logo"],.enrichment-logo img[alt="EPSS logo"],.enrichment-logo img[alt="NVD logo"]{width:25px;height:25px}
.enrichment-logo-fallback{color:#8ff4ff;font-size:15px;font-weight:950}
.enrichment-service strong{display:block;color:#f4f8ff;font-size:12px;line-height:1.15;overflow-wrap:anywhere}
.enrichment-service span:not(.enrichment-logo){display:block;margin-top:3px;color:#91a4ba;font-size:10.5px;line-height:1.22}
.enrichment-service em{grid-column:2;color:#8ff4ff;font-size:9.5px;font-style:normal;font-weight:900;text-transform:uppercase;letter-spacing:.07em}
.flow-node-metrics{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;align-self:center;min-width:0}
.flow-node-metrics span,.flow-format-metrics span{display:grid!important;gap:3px;margin:0!important;min-width:0;border:1px solid rgba(34,211,238,.14);border-radius:10px;padding:7px 8px;background:rgba(34,211,238,.045);box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}
.flow-node-metrics b,.flow-format-metrics b{color:#f5f9ff;font-size:13px;line-height:1;font-weight:950;font-variant-numeric:tabular-nums}
.flow-node-metrics em,.flow-format-metrics em{align-self:auto;color:#91a4ba;font-size:8.5px;line-height:1.1;font-style:normal;font-weight:850;letter-spacing:.05em;text-transform:uppercase;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.flow-format-metrics{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin-top:10px;min-width:0}
.flow-dashboard-node{border-color:rgba(34,211,238,.38);box-shadow:0 16px 42px rgba(0,0,0,.26),0 0 30px rgba(34,211,238,.08),inset 0 1px 0 rgba(255,255,255,.04)}
.flow-output-band{display:grid;grid-template-columns:minmax(640px,1fr) minmax(230px,.28fr);gap:14px;align-items:stretch;min-width:0}
.flow-mac-cluster,.flow-external-cluster{display:grid;grid-template-rows:auto 1fr;gap:12px;min-width:0;border:1px solid rgba(34,211,238,.16);border-radius:14px;padding:14px;background:rgba(7,16,24,.50);box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}
.flow-mac-cluster{background:linear-gradient(135deg,rgba(34,211,238,.045),rgba(7,16,24,.58))}
.flow-external-cluster{border-color:rgba(34,211,238,.20);background:linear-gradient(135deg,rgba(34,211,238,.035),rgba(7,16,24,.66))}
.flow-cluster-heading{display:flex;align-items:center;gap:12px;min-width:0;padding-bottom:10px;border-bottom:1px solid rgba(148,163,184,.10)}
.flow-cluster-heading .flow-logo-ring{width:46px;height:46px;flex:0 0 46px;border-radius:13px}
.flow-cluster-heading .flow-logo-ring img{width:32px;height:32px}
.flow-cluster-heading strong{display:block;color:#f4f8ff;font-size:15px;line-height:1.15}
.flow-cluster-heading span:not(.flow-logo-ring):not(.flow-logo-ring span){display:block;margin-top:4px;color:#91a4ba;font-size:12px;line-height:1.25}
.flow-cluster-grid{display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));gap:10px;min-width:0}
.flow-output-band .flow-system-node{min-height:174px}
.flow-external-cluster .flow-system-node{min-height:0;height:100%}
@keyframes flow-dot-horizontal{0%{left:0;opacity:0;transform:translate(-50%,-50%) scale(.72)}10%,86%{opacity:1}100%{left:100%;opacity:0;transform:translate(-50%,-50%) scale(1.05)}}
@keyframes flow-divider-pulse{0%,100%{opacity:.46;box-shadow:0 0 8px rgba(34,211,238,.12)}50%{opacity:1;box-shadow:0 0 18px rgba(143,244,255,.34),0 0 34px rgba(34,211,238,.18)}}
.flow-summary-grid{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:14px;margin-top:16px}
.flow-summary-card{border:1px solid rgba(148,163,184,.13);border-radius:12px;padding:16px;background:#0d1620;box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}
.flow-summary-card span{display:block;color:#8ff4ff;font-size:11px;font-weight:950;text-transform:uppercase;letter-spacing:.10em}
.flow-summary-card strong{display:block;margin-top:10px;color:#f3f8ff;font-size:17px}
.flow-summary-card em{display:block;margin-top:6px;color:#9aa8b8;font-size:12px;font-style:normal;line-height:1.35}
@media(max-width:1700px){.flow-product-hero{grid-template-columns:1fr}.flow-product-copy{position:static;padding:0 64px 0 0}.flow-summary-grid{grid-template-columns:repeat(4,minmax(0,1fr))}}
@media(max-width:1280px){.flow-lane-ingress{grid-template-columns:repeat(2,minmax(0,1fr))}.flow-lane-ingress .flow-connector{display:none}.flow-lane-outputs{grid-template-columns:repeat(3,minmax(0,1fr))}.flow-enrichment-band,.flow-output-band{grid-template-columns:1fr}.enrichment-service-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.flow-cluster-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:820px){.flow-product-hero{padding:16px;border-radius:14px}.flow-product-copy{padding-right:58px}.flow-product-copy h2{font-size:28px}.flow-product-map{padding:12px}.flow-lane-ingress,.flow-lane-outputs{grid-template-columns:1fr}.flow-lane-ingress .flow-system-node+.flow-system-node,.flow-lane-outputs .flow-system-node+.flow-system-node{margin-top:4px}.flow-downlink span{justify-self:center;width:auto;max-width:90%;margin-right:0;overflow-wrap:anywhere}.enrichment-service-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.flow-summary-grid{grid-template-columns:1fr 1fr}}
@media(max-width:520px){.flow-product-copy{padding-right:0}.flow-privacy-toggle{position:relative;right:auto;top:auto;justify-self:end;margin-bottom:-6px}.flow-product-hero{display:grid;gap:12px}.flow-product-map{gap:12px}.flow-system-node{min-height:132px}.enrichment-service-grid,.flow-cluster-grid{grid-template-columns:1fr}.flow-summary-grid{grid-template-columns:1fr}.flow-node-metrics{grid-template-columns:1fr 1fr}}
</style>
'''

FLOW_PAGE_JS = '''
<script>
(() => {
  const buttons = [...document.querySelectorAll('.flow-privacy-toggle')];
  const addresses = [...document.querySelectorAll('.flow-ip-address')];
  if (!buttons.length || !addresses.length) return;
  const mask = 'xxx.xxx.xxx.xxx';
  let visible = false;
  function applyPrivacyState() {
    addresses.forEach(address => {
      address.textContent = visible ? (address.dataset.ip || '') : mask;
      address.classList.toggle('visible', visible);
    });
    buttons.forEach(button => {
      button.setAttribute('aria-pressed', String(visible));
      button.setAttribute('aria-label', visible ? 'Hide node IP addresses' : 'Show node IP addresses');
      button.setAttribute('title', visible ? 'Hide node IP addresses' : 'Show node IP addresses');
    });
  }
  buttons.forEach(button => button.addEventListener('click', () => {
    visible = !visible;
    applyPrivacyState();
  }));
  applyPrivacyState();
})();
</script>
'''


def inject_flow_assets(text: str) -> str:
    if FLOW_PAGE_CSS not in text:
        text = text.replace('</head>', FLOW_PAGE_CSS + '</head>', 1)
    if FLOW_PAGE_JS not in text:
        text = text.replace('</body>', FLOW_PAGE_JS + '</body>', 1)
    return text


def copy_static_assets() -> None:
    """Copy dashboard image/logo assets beside the generated static pages."""
    destination = OUT_DIR / 'assets'
    destination.mkdir(parents=True, exist_ok=True)
    for source_root in ASSET_SOURCE_DIRS:
        if not source_root.exists():
            continue
        try:
            if source_root.resolve() == destination.resolve():
                continue
        except FileNotFoundError:
            pass
        for source in source_root.rglob('*'):
            if not source.is_file():
                continue
            relative = source.relative_to(source_root)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)


def remove_between_markers(text: str, start_marker: str, end_marker: str) -> str:
    start = text.find(start_marker)
    end = text.find(end_marker, start)
    if start == -1 or end == -1:
        return text
    return text[:start] + text[end:]


def replace_main_page_content(text: str, replacement: str) -> str:
    content_start = text.find('<section id="overview-view"')
    if content_start == -1:
        content_start = text.find('<section id="alerts-view"')
    footer_start = text.find('<div class="footer">', content_start)
    if footer_start == -1:
        footer_start = text.find('<div class="footer"', content_start)
    if content_start == -1 or footer_start == -1:
        return text
    return text[:content_start] + replacement + text[footer_start:]


def render_static_page(shell_html: str, page_key: str, reports: list[AlertReport]) -> str:
    page = PAGE_BY_KEY[page_key]
    active_count = active_alert_count(reports)
    active_severity = active_alert_highest_severity_class(reports)
    data_view = 'alerts' if page_key == 'alerts' else 'overview'
    rendered = shell_html
    rendered = re.sub(r'<title>.*?</title>', f'<title>{html.escape(page["title"])} - Onion Sentinel</title>', rendered, count=1)
    rendered = rendered.replace('<div class="app-shell" data-view="overview">', f'<div class="app-shell" data-view="{data_view}">', 1)
    rendered = re.sub(r'<nav class="nav">.*?</nav>', build_nav_html(page_key, active_count, active_severity), rendered, count=1, flags=re.S)
    rendered = rendered.replace('<div class="health" id="system-health-tile" data-health-state="unknown">', '<a class="health system-health-link" id="system-health-tile" data-health-state="unknown" href="system-health.html" style="display:block;text-decoration:none">', 1)
    rendered = rendered.replace('</span></div><div class="analyst byline">', '</span></a><div class="analyst byline">', 1)
    rendered = rendered.replace('<h1 id="page-title">SOC Overview</h1>', f'<h1 id="page-title">{html.escape(page["title"])}</h1>', 1)
    rendered = rendered.replace('<div id="page-subtitle" class="subtitle">Autonomous SIEM alert enrichment data flow</div>', f'<div id="page-subtitle" class="subtitle">{html.escape(page["subtitle"])}</div>', 1)
    rendered = rendered.replace("setView(appShell?.dataset.view||'overview');", '/* static page navigation is rendered server-side */')

    overview_marker = '<section id="overview-view" class="view-section overview-view" aria-label="SOC Alerts overview">'
    alerts_marker = '<section id="alerts-view" class="view-section alerts-view" aria-label="SOC alert table">'
    footer_marker = '<div class="footer">'
    if page_key == 'home':
        rendered = replace_main_page_content(rendered, executive_home_section(reports))
        rendered = inject_executive_home_assets(rendered)
    elif page_key == 'flow':
        rendered = replace_main_page_content(rendered, flow_page_section(reports))
        rendered = inject_flow_assets(rendered)
    elif page_key == 'alerts':
        rendered = remove_between_markers(rendered, overview_marker, alerts_marker)
        rendered = rendered.replace(alerts_marker, '<section id="alerts-view" class="view-section alerts-view active" aria-label="SOC alert table">', 1)
    elif page_key == 'system_health':
        rendered = replace_main_page_content(rendered, system_health_page_section())
        rendered = inject_system_health_assets(rendered)
    elif page_key == 'settings':
        rendered = replace_main_page_content(rendered, settings_page_section())
        rendered = inject_settings_assets(rendered)
    elif page_key == 'siem_engineering':
        rendered = replace_main_page_content(rendered, siem_engineering_page_section(reports))
        rendered = inject_siem_engineering_assets(rendered)
    elif page_key == 'threat_hunter':
        rendered = replace_main_page_content(rendered, threat_hunter_page_section(reports))
        rendered = inject_threat_hunter_assets(rendered)
    else:
        rendered = replace_main_page_content(rendered, placeholder_page_section(page_key))
    return rendered


def write_site_pages(reports: list[AlertReport]) -> list[Path]:
    shell_html = build_html(reports)
    copy_static_assets()
    written: list[Path] = [write_status_json(reports), write_n8n_beacon_json(reports), write_n8n_beacon_history_json(), *write_detail_fragments(reports)]
    for key, filename, _title, _subtitle in PAGE_DEFS:
        path = OUT_DIR / filename
        path.write_text(render_static_page(shell_html, key, reports), encoding='utf-8')
        written.append(path)
    # Keep a direct SOC Alerts route for bookmarks while making index.html the
    # default SOC Alerts page.
    soc_alerts_path = OUT_DIR / 'soc-alerts.html'
    soc_alerts_path.write_text(render_static_page(shell_html, 'alerts', reports), encoding='utf-8')
    written.append(soc_alerts_path)
    siem_tuning_alias = OUT_DIR / 'siem-tuning.html'
    siem_tuning_alias.write_text(render_static_page(shell_html, 'siem_engineering', reports), encoding='utf-8')
    written.append(siem_tuning_alias)
    return written


def main() -> int:
    reports = load_reports()
    written = write_site_pages(reports)
    print(f'Wrote {INDEX}')
    print('pages=' + ','.join(path.name for path in written))
    print(f'reports={len(reports)} bytes={sum(r.size for r in reports)} source={DB_PATH} markdown_corpus={SOURCE_DIR}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
