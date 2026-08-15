"""Stable schema, defaults, and errors for the CTI program workspace."""
from __future__ import annotations

import copy
import re
import threading
from pathlib import Path


SCHEMA_VERSION = 1
MAX_FILE_BYTES = 256 * 1024
MAX_SOURCES = 100
MAX_TECHNOLOGIES = 250
MAX_REQUIREMENTS = 100
MAX_INTELLIGENCE = 500
MAX_AUDIT_HISTORY = 100
PROGRAM_LOCK = threading.RLock()
DEFAULT_PROGRAM_FILE = (
    Path.home() / "n8n-local" / "config" / "cyber-threat-intel-workspace.json"
)

SOURCE_TYPES = frozenset(
    {
        "government",
        "isac-csirt",
        "vendor",
        "commercial",
        "osint",
        "stix-taxii",
        "internal-telemetry",
        "incident-response",
    }
)
ACQUISITION_METHODS = frozenset(
    {"api", "rss", "taxii", "email", "web", "manual", "internal"}
)
CADENCES = frozenset(
    {"realtime", "hourly", "daily", "weekly", "monthly", "on-demand"}
)
RELIABILITY_LEVELS = frozenset({"A", "B", "C", "D", "E", "F"})
HANDLING_LEVELS = frozenset(
    {"TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"}
)
SOURCE_DISPOSITIONS = frozenset({"retain", "reduce", "replace", "remove"})
SOURCE_COLLECTION_STATUSES = frozenset({"unknown", "healthy", "degraded", "failed"})
TECHNOLOGY_CATEGORIES = frozenset(
    {
        "security-platform",
        "operating-system",
        "application",
        "cloud-service",
        "network",
        "development-tool",
        "library",
        "other",
    }
)
PRIORITIES = frozenset({"critical", "high", "medium", "low"})
EXPOSURES = frozenset(
    {"internet-facing", "internal", "endpoint", "server", "cloud", "mixed", "unknown"}
)
REQUIREMENT_STATUSES = frozenset({"draft", "active", "answered", "paused", "retired"})
LIFECYCLE_STATES = (
    "requirements",
    "collection",
    "processing",
    "analysis",
    "dissemination",
    "feedback",
    "evaluation",
)
LIFECYCLE_STATE_SET = frozenset(LIFECYCLE_STATES)
INFORMATION_CREDIBILITY_LEVELS = frozenset({"1", "2", "3", "4", "5", "6"})
CONFIDENCE_LEVELS = frozenset({"high", "moderate", "low", "unknown"})
EVIDENCE_KINDS = frozenset(
    {
        "source-record",
        "advisory",
        "report",
        "telemetry",
        "pcap",
        "analyst-note",
        "case-artifact",
        "other",
    }
)
ENTITY_TYPES = frozenset(
    {"indicator", "actor", "campaign", "vulnerability", "defensive-action"}
)
INVESTIGATION_USE = "context-only"
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")
SECRET_REFERENCE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,79}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{2,499}$")

SOURCE_FIELDS = frozenset(
    {
        "id",
        "enabled",
        "name",
        "source_type",
        "acquisition",
        "endpoint",
        "credential_reference",
        "owner",
        "cadence",
        "reliability",
        "handling",
        "requirements",
        "review_date",
        "disposition",
        "collection_status",
        "last_attempt_at",
        "last_success_at",
        "failure_code",
        "notes",
    }
)
REQUIREMENT_FIELDS = frozenset(
    {
        "id",
        "active",
        "title",
        "decision",
        "sponsor",
        "consumers",
        "priority",
        "horizon",
        "cadence",
        "collection_gaps",
        "deliverable",
        "success_criteria",
        "review_date",
        "status",
    }
)
INTELLIGENCE_FIELDS = frozenset(
    {
        "id",
        "deduplication_key",
        "title",
        "lifecycle_state",
        "requirement_ids",
        "source_ids",
        "affected_technology_ids",
        "source_reliability",
        "information_credibility",
        "confidence",
        "handling",
        "collected_at",
        "analyzed_at",
        "published_at",
        "expires_at",
        "summary",
        "analytic_judgment",
        "assumptions",
        "alternatives",
        "evidence",
        "entities",
        "investigation_use",
    }
)
EVIDENCE_FIELDS = frozenset(
    {"id", "kind", "reference", "description", "observed_at", "source_id", "handling"}
)
ENTITY_FIELDS = frozenset(
    {"id", "entity_type", "value", "evidence_ids", "affected_technology_ids"}
)
AUDIT_FIELDS = frozenset(
    {"revision", "event", "changed_at", "changes", "before_digest", "after_digest"}
)
TECHNOLOGY_FIELDS = frozenset(
    {
        "id",
        "enabled",
        "vendor",
        "product",
        "category",
        "versions",
        "deployment_scope",
        "criticality",
        "priority",
        "exposure",
        "owner",
        "monitor_for",
        "requirements",
        "review_date",
        "notes",
    }
)


class CTIProgramError(ValueError):
    """Base error safe to return through the CTI configuration API."""


class CTIProgramConflict(CTIProgramError):
    """Raised when an optimistic revision check detects a concurrent edit."""


CTIProgramError.__module__ = "cti_program"
CTIProgramConflict.__module__ = "cti_program"


DEFAULT_SOURCES = (
    {
        "id": "cisa-kev",
        "enabled": True,
        "name": "CISA Known Exploited Vulnerabilities",
        "source_type": "government",
        "acquisition": "web",
        "endpoint": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "credential_reference": "",
        "owner": "CTI Program",
        "cadence": "daily",
        "reliability": "A",
        "handling": "TLP:CLEAR",
        "requirements": ["Exploited vulnerabilities affecting monitored technology"],
        "review_date": "",
        "disposition": "retain",
        "notes": "Authoritative exploitation evidence for vulnerability prioritization.",
    },
    {
        "id": "cisa-advisories",
        "enabled": True,
        "name": "CISA Cybersecurity Advisories",
        "source_type": "government",
        "acquisition": "web",
        "endpoint": "https://www.cisa.gov/news-events/cybersecurity-advisories",
        "credential_reference": "",
        "owner": "CTI Program",
        "cadence": "daily",
        "reliability": "A",
        "handling": "TLP:CLEAR",
        "requirements": ["Campaigns and vulnerabilities requiring defensive action"],
        "review_date": "",
        "disposition": "retain",
        "notes": "Government advisories and joint guidance; validate applicability locally.",
    },
    {
        "id": "mitre-attack",
        "enabled": True,
        "name": "MITRE ATT&CK",
        "source_type": "osint",
        "acquisition": "web",
        "endpoint": "https://attack.mitre.org/",
        "credential_reference": "",
        "owner": "Detection Engineering",
        "cadence": "monthly",
        "reliability": "A",
        "handling": "TLP:CLEAR",
        "requirements": ["Behavior and detection coverage mapping"],
        "review_date": "",
        "disposition": "retain",
        "notes": "Behavioral framework; technique mappings still require direct evidence.",
    },
    {
        "id": "first-epss",
        "enabled": True,
        "name": "FIRST EPSS",
        "source_type": "osint",
        "acquisition": "api",
        "endpoint": "https://api.first.org/data/v1/epss",
        "credential_reference": "",
        "owner": "Vulnerability Management",
        "cadence": "daily",
        "reliability": "B",
        "handling": "TLP:CLEAR",
        "requirements": ["Likelihood-informed vulnerability prioritization"],
        "review_date": "",
        "disposition": "retain",
        "notes": "Probability signal, not proof of exploitation or local impact.",
    },
    {
        "id": "nvd",
        "enabled": True,
        "name": "NIST National Vulnerability Database",
        "source_type": "government",
        "acquisition": "api",
        "endpoint": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "credential_reference": "NVD_API_KEY",
        "owner": "Vulnerability Management",
        "cadence": "daily",
        "reliability": "B",
        "handling": "TLP:CLEAR",
        "requirements": ["Vulnerabilities affecting monitored technology"],
        "review_date": "",
        "disposition": "retain",
        "notes": "Use vendor advisories and local exposure to resolve enrichment gaps.",
    },
    {
        "id": "onion-sentinel-telemetry",
        "enabled": True,
        "name": "Onion Sentinel local telemetry",
        "source_type": "internal-telemetry",
        "acquisition": "internal",
        "endpoint": "",
        "credential_reference": "",
        "owner": "SOC",
        "cadence": "realtime",
        "reliability": "A",
        "handling": "TLP:AMBER+STRICT",
        "requirements": ["Local sightings, prevalence, and defensive relevance"],
        "review_date": "",
        "disposition": "retain",
        "notes": "Security Onion, Zeek, Suricata, PCAP, osquery, and analyst findings.",
    },
)

DEFAULT_TECHNOLOGIES = (
    {
        "id": "security-onion",
        "enabled": True,
        "vendor": "Security Onion Solutions",
        "product": "Security Onion",
        "category": "security-platform",
        "versions": "Deployed version(s)",
        "deployment_scope": "Security monitoring platform",
        "criticality": "critical",
        "priority": "critical",
        "exposure": "internal",
        "owner": "Security Operations",
        "monitor_for": ["security advisories", "release notes", "Elasticsearch", "Fleet", "sensor"],
        "requirements": ["Threats and vulnerabilities affecting monitoring continuity"],
        "review_date": "",
        "notes": "Reconcile exact versions and assets with Software Inventory.",
    },
    {
        "id": "elastic-stack",
        "enabled": True,
        "vendor": "Elastic",
        "product": "Elastic Stack",
        "category": "security-platform",
        "versions": "Deployed version(s)",
        "deployment_scope": "SIEM search and storage",
        "criticality": "critical",
        "priority": "critical",
        "exposure": "internal",
        "owner": "SIEM Engineering",
        "monitor_for": ["Elasticsearch", "Kibana", "Logstash", "Elastic Agent", "CVE"],
        "requirements": ["Threats affecting SIEM confidentiality, integrity, or availability"],
        "review_date": "",
        "notes": "Track upstream advisories and the version bundled with Security Onion.",
    },
    {
        "id": "osquery",
        "enabled": True,
        "vendor": "osquery Foundation",
        "product": "osquery",
        "category": "security-platform",
        "versions": "Deployed version(s)",
        "deployment_scope": "Endpoint query and response",
        "criticality": "high",
        "priority": "high",
        "exposure": "endpoint",
        "owner": "Incident Response",
        "monitor_for": ["osquery", "extension", "Fleet", "security advisory"],
        "requirements": ["Threats affecting endpoint evidence collection"],
        "review_date": "",
        "notes": "Keep watchlist scope separate from endpoint inventory truth.",
    },
    {
        "id": "apple-macos",
        "enabled": True,
        "vendor": "Apple",
        "product": "macOS",
        "category": "operating-system",
        "versions": "Observed supported versions",
        "deployment_scope": "Analyst and service hosts",
        "criticality": "high",
        "priority": "high",
        "exposure": "endpoint",
        "owner": "Endpoint Operations",
        "monitor_for": ["macOS", "Safari", "WebKit", "XProtect", "Gatekeeper"],
        "requirements": ["Actively exploited vulnerabilities affecting Mac assets"],
        "review_date": "",
        "notes": "Prioritize Apple security releases with local asset/version evidence.",
    },
    {
        "id": "docker-desktop",
        "enabled": True,
        "vendor": "Docker",
        "product": "Docker Desktop",
        "category": "development-tool",
        "versions": "Observed version(s)",
        "deployment_scope": "Local container runtime",
        "criticality": "medium",
        "priority": "medium",
        "exposure": "endpoint",
        "owner": "Platform Operations",
        "monitor_for": ["Docker Desktop", "Docker Engine", "containerd", "BuildKit"],
        "requirements": ["Container runtime vulnerabilities affecting local services"],
        "review_date": "",
        "notes": "Link exact observed packages to the Software Inventory page.",
    },
)


def _default_program() -> dict[str, object]:
    sources = copy.deepcopy(list(DEFAULT_SOURCES))
    for source in sources:
        source.setdefault("collection_status", "unknown")
        source.setdefault("last_attempt_at", "")
        source.setdefault("last_success_at", "")
        source.setdefault("failure_code", "")
    return {
        "schema_version": SCHEMA_VERSION,
        "revision": 0,
        "updated_at": "",
        "sources": sources,
        "technologies": copy.deepcopy(list(DEFAULT_TECHNOLOGIES)),
        "requirements": [],
        "intelligence": [],
        "audit_history": [],
    }


_default_program.__module__ = "cti_program"

__all__ = tuple(
    name for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
)
