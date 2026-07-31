"""Validated, owner-managed configuration for the CTI program workspace.

The workspace intentionally stores governance metadata only.  Credentials stay
in Onion Sentinel's private environment/secret store and are referenced by name.
"""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import re
import stat
import threading
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from scripts.atomic_io import atomic_write_json


SCHEMA_VERSION = 1
MAX_FILE_BYTES = 256 * 1024
MAX_SOURCES = 100
MAX_TECHNOLOGIES = 250
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
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")
SECRET_REFERENCE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,79}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

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
        "notes",
    }
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


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _default_program() -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "revision": 0,
        "updated_at": "",
        "sources": copy.deepcopy(list(DEFAULT_SOURCES)),
        "technologies": copy.deepcopy(list(DEFAULT_TECHNOLOGIES)),
    }


def _text(value: object, field: str, limit: int, *, required: bool = False) -> str:
    if not isinstance(value, str):
        raise CTIProgramError(f"{field} must be text.")
    normalized = value.strip()
    if required and not normalized:
        raise CTIProgramError(f"{field} is required.")
    if len(normalized) > limit:
        raise CTIProgramError(f"{field} exceeds {limit} characters.")
    if any(ord(char) < 32 and char not in "\n\t" for char in normalized):
        raise CTIProgramError(f"{field} contains an unsupported control character.")
    return normalized


def _enum(value: object, field: str, allowed: frozenset[str]) -> str:
    normalized = _text(value, field, 64, required=True)
    if normalized not in allowed:
        raise CTIProgramError(f"{field} has an unsupported value.")
    return normalized


def _identifier(value: object, field: str) -> str:
    normalized = _text(value, field, 64)
    if not normalized:
        normalized = uuid.uuid4().hex
    if not IDENTIFIER_RE.fullmatch(normalized):
        raise CTIProgramError(f"{field} must contain only lowercase letters, digits, hyphens, or underscores.")
    return normalized


def _date(value: object, field: str) -> str:
    normalized = _text(value, field, 10)
    if not normalized:
        return ""
    if not DATE_RE.fullmatch(normalized):
        raise CTIProgramError(f"{field} must use YYYY-MM-DD.")
    try:
        dt.date.fromisoformat(normalized)
    except ValueError as exc:
        raise CTIProgramError(f"{field} is not a valid date.") from exc
    return normalized


def _string_list(value: object, field: str, *, maximum: int = 16) -> list[str]:
    if not isinstance(value, list):
        raise CTIProgramError(f"{field} must be a list.")
    if len(value) > maximum:
        raise CTIProgramError(f"{field} exceeds {maximum} entries.")
    result: list[str] = []
    seen: set[str] = set()
    for index, entry in enumerate(value):
        normalized = _text(entry, f"{field}[{index}]", 120, required=True)
        key = normalized.casefold()
        if key not in seen:
            seen.add(key)
            result.append(normalized)
    return result


def _endpoint(value: object, field: str) -> str:
    normalized = _text(value, field, 500)
    if not normalized:
        return ""
    parsed = urlsplit(normalized)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise CTIProgramError(
            f"{field} must be an http(s) URL without credentials, query parameters, or fragments."
        )
    return normalized


def _secret_reference(value: object, field: str) -> str:
    normalized = _text(value, field, 80)
    if normalized and not SECRET_REFERENCE_RE.fullmatch(normalized):
        raise CTIProgramError(
            f"{field} must be an environment-variable name, not a credential value."
        )
    return normalized


def _normalize_source(value: object, index: int) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CTIProgramError(f"sources[{index}] must be an object.")
    unknown = set(value) - SOURCE_FIELDS
    if unknown:
        raise CTIProgramError(f"sources[{index}] contains unsupported fields: {', '.join(sorted(unknown))}.")
    enabled = value.get("enabled")
    if not isinstance(enabled, bool):
        raise CTIProgramError(f"sources[{index}].enabled must be true or false.")
    return {
        "id": _identifier(value.get("id", ""), f"sources[{index}].id"),
        "enabled": enabled,
        "name": _text(value.get("name", ""), f"sources[{index}].name", 120, required=True),
        "source_type": _enum(value.get("source_type", ""), f"sources[{index}].source_type", SOURCE_TYPES),
        "acquisition": _enum(value.get("acquisition", ""), f"sources[{index}].acquisition", ACQUISITION_METHODS),
        "endpoint": _endpoint(value.get("endpoint", ""), f"sources[{index}].endpoint"),
        "credential_reference": _secret_reference(value.get("credential_reference", ""), f"sources[{index}].credential_reference"),
        "owner": _text(value.get("owner", ""), f"sources[{index}].owner", 100, required=True),
        "cadence": _enum(value.get("cadence", ""), f"sources[{index}].cadence", CADENCES),
        "reliability": _enum(value.get("reliability", ""), f"sources[{index}].reliability", RELIABILITY_LEVELS),
        "handling": _enum(value.get("handling", ""), f"sources[{index}].handling", HANDLING_LEVELS),
        "requirements": _string_list(value.get("requirements", []), f"sources[{index}].requirements"),
        "review_date": _date(value.get("review_date", ""), f"sources[{index}].review_date"),
        "disposition": _enum(value.get("disposition", ""), f"sources[{index}].disposition", SOURCE_DISPOSITIONS),
        "notes": _text(value.get("notes", ""), f"sources[{index}].notes", 1200),
    }


def _normalize_technology(value: object, index: int) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CTIProgramError(f"technologies[{index}] must be an object.")
    unknown = set(value) - TECHNOLOGY_FIELDS
    if unknown:
        raise CTIProgramError(f"technologies[{index}] contains unsupported fields: {', '.join(sorted(unknown))}.")
    enabled = value.get("enabled")
    if not isinstance(enabled, bool):
        raise CTIProgramError(f"technologies[{index}].enabled must be true or false.")
    return {
        "id": _identifier(value.get("id", ""), f"technologies[{index}].id"),
        "enabled": enabled,
        "vendor": _text(value.get("vendor", ""), f"technologies[{index}].vendor", 100, required=True),
        "product": _text(value.get("product", ""), f"technologies[{index}].product", 120, required=True),
        "category": _enum(value.get("category", ""), f"technologies[{index}].category", TECHNOLOGY_CATEGORIES),
        "versions": _text(value.get("versions", ""), f"technologies[{index}].versions", 180),
        "deployment_scope": _text(value.get("deployment_scope", ""), f"technologies[{index}].deployment_scope", 240),
        "criticality": _enum(value.get("criticality", ""), f"technologies[{index}].criticality", PRIORITIES),
        "priority": _enum(value.get("priority", ""), f"technologies[{index}].priority", PRIORITIES),
        "exposure": _enum(value.get("exposure", ""), f"technologies[{index}].exposure", EXPOSURES),
        "owner": _text(value.get("owner", ""), f"technologies[{index}].owner", 100, required=True),
        "monitor_for": _string_list(value.get("monitor_for", []), f"technologies[{index}].monitor_for", maximum=24),
        "requirements": _string_list(value.get("requirements", []), f"technologies[{index}].requirements"),
        "review_date": _date(value.get("review_date", ""), f"technologies[{index}].review_date"),
        "notes": _text(value.get("notes", ""), f"technologies[{index}].notes", 1200),
    }


def normalize_program(value: object, *, stored: bool = False) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CTIProgramError("CTI workspace must be a JSON object.")
    allowed = {"schema_version", "revision", "updated_at", "sources", "technologies"}
    unknown = set(value) - allowed
    if unknown:
        raise CTIProgramError(f"CTI workspace contains unsupported fields: {', '.join(sorted(unknown))}.")
    schema_version = value.get("schema_version", SCHEMA_VERSION)
    if schema_version != SCHEMA_VERSION:
        raise CTIProgramError(f"Unsupported CTI workspace schema version: {schema_version!r}.")
    revision = value.get("revision", 0)
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise CTIProgramError("revision must be a non-negative integer.")
    updated_at = _text(value.get("updated_at", ""), "updated_at", 40)
    sources_value = value.get("sources", [])
    technologies_value = value.get("technologies", [])
    if not isinstance(sources_value, list) or len(sources_value) > MAX_SOURCES:
        raise CTIProgramError(f"sources must be a list with at most {MAX_SOURCES} entries.")
    if not isinstance(technologies_value, list) or len(technologies_value) > MAX_TECHNOLOGIES:
        raise CTIProgramError(f"technologies must be a list with at most {MAX_TECHNOLOGIES} entries.")
    sources = [_normalize_source(item, index) for index, item in enumerate(sources_value)]
    technologies = [_normalize_technology(item, index) for index, item in enumerate(technologies_value)]
    source_ids: set[str] = set()
    source_names: set[str] = set()
    for source in sources:
        identifier = str(source["id"])
        name = str(source["name"]).casefold()
        if identifier in source_ids or name in source_names:
            raise CTIProgramError("CTI source ids and names must be unique.")
        source_ids.add(identifier)
        source_names.add(name)
    technology_ids: set[str] = set()
    technology_names: set[tuple[str, str]] = set()
    for technology in technologies:
        identifier = str(technology["id"])
        name = (str(technology["vendor"]).casefold(), str(technology["product"]).casefold())
        if identifier in technology_ids or name in technology_names:
            raise CTIProgramError("Technology ids and vendor/product pairs must be unique.")
        technology_ids.add(identifier)
        technology_names.add(name)
    return {
        "schema_version": SCHEMA_VERSION,
        "revision": revision,
        "updated_at": updated_at if stored else "",
        "sources": sources,
        "technologies": technologies,
    }


def _safe_metadata(path: Path) -> os.stat_result:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CTIProgramError("CTI workspace path is not a regular file.")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise CTIProgramError("CTI workspace is not owned by the service account.")
    if metadata.st_size > MAX_FILE_BYTES:
        raise CTIProgramError(f"CTI workspace exceeds {MAX_FILE_BYTES} bytes.")
    return metadata


def load_program(path: Path | None = None) -> dict[str, object]:
    destination = DEFAULT_PROGRAM_FILE if path is None else Path(path)
    with PROGRAM_LOCK:
        if not destination.exists():
            return _default_program()
        _safe_metadata(destination)
        try:
            raw = destination.read_bytes()
            if len(raw) > MAX_FILE_BYTES:
                raise CTIProgramError(f"CTI workspace exceeds {MAX_FILE_BYTES} bytes.")
            parsed = json.loads(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise CTIProgramError("CTI workspace is not valid UTF-8.") from exc
        except json.JSONDecodeError as exc:
            raise CTIProgramError("CTI workspace is not valid JSON.") from exc
        return normalize_program(parsed, stored=True)


def save_program(payload: object, path: Path | None = None) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise CTIProgramError("Request body must be a JSON object.")
    allowed = {"expected_revision", "sources", "technologies"}
    unknown = set(payload) - allowed
    if unknown:
        raise CTIProgramError(f"Request contains unsupported fields: {', '.join(sorted(unknown))}.")
    expected_revision = payload.get("expected_revision")
    if not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0:
        raise CTIProgramError("expected_revision must be a non-negative integer.")
    destination = DEFAULT_PROGRAM_FILE if path is None else Path(path)
    with PROGRAM_LOCK:
        current = load_program(destination)
        if int(current["revision"]) != expected_revision:
            raise CTIProgramConflict(
                "The CTI workspace changed in another session. Reload it before saving."
            )
        candidate = normalize_program(
            {
                "schema_version": SCHEMA_VERSION,
                "revision": expected_revision,
                "updated_at": "",
                "sources": payload.get("sources", []),
                "technologies": payload.get("technologies", []),
            }
        )
        candidate["revision"] = expected_revision + 1
        candidate["updated_at"] = _now()
        rendered = json.dumps(candidate, indent=2, sort_keys=True).encode("utf-8")
        if len(rendered) > MAX_FILE_BYTES:
            raise CTIProgramError(f"CTI workspace exceeds {MAX_FILE_BYTES} bytes.")
        atomic_write_json(destination, candidate, mode=0o600)
        return candidate


def program_digest(program: dict[str, object]) -> str:
    """Return a content digest suitable for metadata-only mutation logging."""
    payload = json.dumps(program, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def public_response(program: dict[str, object]) -> dict[str, object]:
    return {
        "ok": True,
        "program": program,
        "editing": {
            "requires_admin": True,
            "credentials_are_references_only": True,
        },
        "limits": {
            "sources": MAX_SOURCES,
            "technologies": MAX_TECHNOLOGIES,
            "bytes": MAX_FILE_BYTES,
        },
    }
