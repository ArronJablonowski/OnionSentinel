#!/usr/bin/env python3
"""Environment-derived defaults and immutable prompt-builder policy."""
from __future__ import annotations

import os
from pathlib import Path
import re

import investigation_query_contract as INVESTIGATION_CONTRACT


INVESTIGATION_CONTRACT_PACKS = INVESTIGATION_CONTRACT.PACKS
INVESTIGATION_EVENT_TUPLE_ATOM_RE = INVESTIGATION_CONTRACT.SAFE_ATOM_RE
EVENT_TUPLE_PATHS = getattr(
    INVESTIGATION_CONTRACT,
    "EVENT_TUPLE_PATHS",
    {
        field: (path,)
        for field, path in INVESTIGATION_CONTRACT.EVENT_TUPLE_FIELDS.items()
    },
)
PACK_ROLE_MODE = getattr(INVESTIGATION_CONTRACT, "PACK_ROLE_MODE", {})


HOME = Path.home()
DEFAULT_DB = HOME / "n8n-local" / "alert_store_data" / "alerts.sqlite3"
DEFAULT_ROLLUPS = HOME / "n8n-local" / "soc-alerts" / "daily-rollups"
DEFAULT_OUT = HOME / "n8n-local" / "soc-alerts" / "ai-prompts"
DEFAULT_SYSTEM_PROMPT_FILE = (
    HOME / "n8n-local" / "config" / "soc_analyst_system_prompt.md"
)
DEFAULT_SECOND_OPINION_PROMPT_FILE = (
    HOME / "n8n-local" / "config" / "soc_analyst_second_opinion_prompt.md"
)
DEFAULT_AGENT_MEMORY_DIR = HOME / "n8n-local" / "soc-alerts" / "agent-memory"
DEFAULT_PCAP_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "pcap-analysis"
DEFAULT_AI_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-analysis"
DEFAULT_DETECTION_PLAYBOOKS_FILE = (
    HOME / "n8n-local" / "config" / "detection_playbooks.json"
)
DEFAULT_INVESTIGATION_SKILLS_FILE = (
    HOME / "n8n-local" / "config" / "investigation_skills.json"
)
DEFAULT_ASSET_INVENTORY_FILE = (
    HOME
    / "n8n-local"
    / "config"
    / "asset_inventory.database-export.json"
)
DEFAULT_SOC_ANALYST_MEMORY_FILE = (
    DEFAULT_AGENT_MEMORY_DIR / "soc-analyst-memory.md"
)
DEFAULT_SHARED_AGENT_MEMORY_FILE = (
    DEFAULT_AGENT_MEMORY_DIR / "shared-agent-memory.md"
)
DEFAULT_SYSTEM_PROMPT = (
    "You are a careful SOC analyst assisting with Security Onion alerts."
)
TEST_PREFIXES = (
    "phase%",
    "config-%",
    "internal-test-%",
    "sqlite-%",
    "policy-%",
    "codex-%",
)
DEFAULT_MAX_PACKAGE_BYTES = max(
    256 * 1024,
    int(
        os.environ.get(
            "SOC_AI_MAX_PROMPT_PACKAGE_BYTES",
            str(4 * 1024 * 1024),
        )
    ),
)
MAX_ARTIFACT_JSON_BYTES = max(
    64 * 1024,
    int(
        os.environ.get(
            "SOC_AI_MAX_ARTIFACT_JSON_BYTES",
            str(2 * 1024 * 1024),
        )
    ),
)
MAX_INCIDENT_EVIDENCE_BYTES = 8 * 1024 * 1024
MAX_SYSTEM_PROMPT_BYTES = max(
    8 * 1024,
    int(
        os.environ.get(
            "SOC_AI_MAX_SYSTEM_PROMPT_BYTES",
            str(64 * 1024),
        )
    ),
)
LEGACY_ARTIFACT_SCAN_LIMIT = max(
    10,
    int(os.environ.get("SOC_AI_LEGACY_ARTIFACT_SCAN_LIMIT", "200")),
)
INVESTIGATION_QUERY_CONTRACT = (
    INVESTIGATION_CONTRACT.INVESTIGATION_QUERY_CONTRACT
)
INVESTIGATION_QUERY_V2 = (
    INVESTIGATION_QUERY_CONTRACT
    == "onion-sentinel-investigation-pivots-v2"
)
INVESTIGATION_QUERY_MAX_ROUNDS = 3
INVESTIGATION_QUERY_MAX_TOTAL = 12
INVESTIGATION_QUERY_MAX_PER_ROUND = 4
INVESTIGATION_QUERY_PACKS = (
    "alert_context",
    "network_flow",
    "dns_activity",
    "system_auth",
    "zeek_tls",
    "zeek_http",
    "zeek_files",
    "zeek_ssh",
    "zeek_stun",
    "zeek_quic",
    "zeek_anomalies",
    "osquery_history",
    "cross_sensor_timeline",
)
INVESTIGATION_QUERY_PACK_DESCRIPTIONS = {
    "alert_context": "Suricata and Sigma detection records.",
    "network_flow": (
        "Zeek connection, endpoint network, and alert flow metadata."
    ),
    "dns_activity": "Zeek DNS and endpoint network DNS metadata.",
    "system_auth": (
        "System authentication outcomes, exact users, hosts, and source IPs."
    ),
    "zeek_tls": (
        "Zeek TLS/SSL metadata, SNI, validation, versions, ciphers, "
        "and JA fingerprints."
    ),
    "zeek_http": (
        "Zeek HTTP methods, hosts, URIs, status, sizes, and user agents."
    ),
    "zeek_files": (
        "Zeek file-transfer metadata, MIME types, sizes, analyzers, and hashes."
    ),
    "zeek_ssh": (
        "Zeek SSH authentication, versions, algorithms, and HASSH metadata."
    ),
    "zeek_stun": "Zeek STUN and STUN NAT metadata.",
    "zeek_quic": (
        "Zeek QUIC protocol, version, connection IDs, and server-name metadata."
    ),
    "zeek_anomalies": "Zeek notice, weird, and analyzer anomaly metadata.",
    "osquery_history": (
        "Historical endpoint and osquery-manager events stored in Elastic."
    ),
    "cross_sensor_timeline": (
        "Bounded alert, Zeek connection/DNS, and endpoint event timeline."
    ),
}
INVESTIGATION_SECURITY_ONION_PURPOSES = (
    "validate_detection",
    "establish_timeline",
    "correlate_observable",
    "measure_prevalence",
    "identify_related_activity",
    "test_benign_hypothesis",
)
INVESTIGATION_DERIVED_OPERATIONS = (
    "coverage",
    "connections",
    "dns",
    "tls",
    "http",
    "files",
    "notices",
    "weird",
    "protocols",
    "packet_facts",
    "icmp_facts",
    "icmp_anomalies",
    "user_agents",
    "tls_versions",
    "geoip",
)
INVESTIGATION_DERIVED_FILTERS = {
    "common_flow": [
        "source_ip",
        "destination_ip",
        "endpoint_ip",
        "source_port",
        "destination_port",
        "port",
        "transport",
        "protocol",
        "start_epoch",
        "end_epoch",
    ],
    "connections": ["service", "connection_state"],
    "dns": ["query", "answer", "answer_type", "qtype", "rcode"],
    "tls": ["sni", "version", "cipher", "established"],
    "http": ["host", "uri", "uri_prefix", "method", "status_code", "user_agent"],
    "files": ["mime_type", "filename", "sha256"],
    "notices": ["note", "message"],
    "weird": ["name", "additional"],
    "packet_facts": [
        "query",
        "answer",
        "rcode",
        "sni",
        "version",
        "host",
        "uri",
        "uri_prefix",
        "user_agent",
        "frame_length_min",
        "frame_length_max",
        "icmp_type",
        "icmp_code",
    ],
    "icmp_facts": [
        "family",
        "icmp_type",
        "icmp_code",
        "identifier",
        "sequence",
        "frame_length_min",
        "frame_length_max",
        "payload_length_min",
        "payload_length_max",
        "selected_scope_match",
    ],
    "geoip": ["ip", "country_iso_code", "asn"],
}
ALERT_INDEX_RE = re.compile(
    r"^(?:"
    r"logs-(?:suricata\.alerts|detections\.alerts)-so"
    r"|\.ds-logs-(?:suricata\.alerts|detections\.alerts)-so-\d{4}\.\d{2}\.\d{2}-\d{6}"
    r")$"
)
SAFE_ELASTIC_ID_RE = re.compile(r"^[A-Za-z0-9_.:@+=-]{1,512}$")
SAFE_PIVOT_ATOM_RE = re.compile(r"^[A-Za-z0-9_.:@+-]{1,255}$")
SAFE_PIVOT_DOMAIN_RE = re.compile(
    r"(?i)^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
MAX_DETECTION_GROUP_ROWS = 5000
