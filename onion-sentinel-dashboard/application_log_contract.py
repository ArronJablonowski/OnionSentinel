"""Immutable schemas and allowlists for dashboard application logs."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final


DEFAULT_TAIL_LINES: Final = 200
MAX_TAIL_LINES: Final = 500
MAX_TAIL_BYTES: Final = 512 * 1024
MAX_ENV_BYTES: Final = 1024 * 1024
DEFAULT_ROTATION_BYTES: Final = 10 * 1024 * 1024
DEFAULT_ROTATION_BACKUPS: Final = 5
DEFAULT_RETENTION_DAYS: Final = 30
ANALYSIS_ROTATION_BYTES: Final = 50 * 1024 * 1024
ANALYSIS_ROTATION_BACKUPS: Final = 10
DISK_PRESSURE_PERCENT: Final = 75
MAX_FAMILY_MEMBERS: Final = 50

LOG_ID_RE: Final = re.compile(r"[a-z0-9][a-z0-9-]{0,79}")
ENSURE_STACK_RE: Final = re.compile(r"ensure-n8n-stack-\d{8}-\d{6}Z\.log")
SECRET_ASSIGNMENT_RE: Final = re.compile(
    r"(?i)(\b(?:authorization|proxy-authorization|password|passwd|secret|"
    r"token|access[_-]?token|refresh[_-]?token|api[_-]?key|credential|"
    r"client[_-]?secret)\b\"?\s*[=:]\s*\"?)([^\"\s,;]+)"
)
BEARER_RE: Final = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+")
COOKIE_RE: Final = re.compile(r"(?im)^(\s*(?:Cookie|Set-Cookie)\s*:\s*).*$")
AUTHORIZATION_RE: Final = re.compile(
    r"(?im)^(\s*(?:Authorization|Proxy-Authorization)\s*:\s*).*$"
)
PRIVATE_KEY_RE: Final = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
    r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.DOTALL,
)


class ApplicationLogError(Exception):
    """A safe client-facing application-log error."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = int(status)
        self.message = str(message)


@dataclass(frozen=True)
class LogSpec:
    id: str
    label: str
    category: str
    root: str
    basename: str
    description: str
    format: str = "text"
    rotation: str = "Producer-managed bounded rotation"
    retention: str = "Maximum 30-day retention"
    backups: int = 0
    bounded: bool = False
    family: bool = False
    owner: str = "Onion Sentinel operations"
    path_class: str = "runtime"
    maximum_size_bytes: int = DEFAULT_ROTATION_BYTES
    compression: str = "none"
    disk_pressure: str = "Preserve current file; prune oldest retained generation first"
    retention_days: int = DEFAULT_RETENTION_DAYS
    maintenance: bool = False


STRUCTURED_SPECS: Final = (
    LogSpec(
        "onion-sentinel-application",
        "Onion Sentinel web application",
        "Application",
        "runtime",
        "onion-sentinel-application.jsonl",
        "HTTP requests and audited application events from the dedicated web service.",
        "JSON Lines",
        "At 10 MiB; 5 numbered backups",
        "Current file plus 5 backups (about 60 MiB maximum)",
        DEFAULT_ROTATION_BACKUPS,
        True,
        owner="Onion Sentinel web service",
    ),
    LogSpec(
        "alert-store-application",
        "Alert Store application",
        "Application",
        "runtime",
        "alert-store-application.jsonl",
        "Structured Alert Store lifecycle, API, and persistence events.",
        "JSON Lines",
        "At the configured size; numbered backups",
        "Controlled by ALERT_STORE_APPLICATION_LOG_* settings",
        DEFAULT_ROTATION_BACKUPS,
        True,
        owner="Alert Store service",
    ),
    LogSpec(
        "investigation-harness",
        "Investigation harness",
        "Investigation",
        "runtime",
        "investigation-harness.jsonl",
        "Structured harness execution, evidence, reviewer, and outcome events.",
        "JSON Lines",
        "At 10 MiB; 5 numbered backups",
        "Current file plus 5 backups (about 60 MiB maximum)",
        DEFAULT_ROTATION_BACKUPS,
        True,
        owner="Investigation harness",
    ),
    LogSpec(
        "software-inventory",
        "Software Inventory collector",
        "Inventory",
        "runtime",
        "software-inventory.jsonl",
        "Structured Software Inventory collection and normalization events.",
        "JSON Lines",
        "At 10 MiB; 5 numbered backups",
        "Current file plus 5 backups (about 60 MiB maximum)",
        DEFAULT_ROTATION_BACKUPS,
        True,
        owner="Software Inventory collector",
    ),
    LogSpec(
        "endpoint-software-inventory",
        "Endpoint Software Inventory collector",
        "Inventory",
        "runtime",
        "endpoint-software-inventory.jsonl",
        "Structured scheduled endpoint inventory, retry, and preflight events.",
        "JSON Lines",
        "At 10 MiB; 5 numbered backups",
        "Current file plus 5 backups (about 60 MiB maximum)",
        DEFAULT_ROTATION_BACKUPS,
        True,
        owner="Endpoint Software Inventory collector",
    ),
    LogSpec(
        "dhcp-asset-discovery",
        "DHCP asset discovery",
        "Inventory",
        "runtime",
        "dhcp-asset-discovery.jsonl",
        "Structured DHCP and asset-observation collection events.",
        "JSON Lines",
        "At 10 MiB; 5 numbered backups",
        "Current file plus 5 backups (about 60 MiB maximum)",
        DEFAULT_ROTATION_BACKUPS,
        True,
        owner="DHCP asset discovery collector",
    ),
    LogSpec(
        "dhcp-asset-review",
        "DHCP asset review",
        "Inventory",
        "runtime",
        "dhcp-asset-review.jsonl",
        "Structured operator review and asset-promotion events, when used.",
        "JSON Lines",
        "At 10 MiB; 5 numbered backups",
        "Current file plus 5 backups (about 60 MiB maximum)",
        DEFAULT_ROTATION_BACKUPS,
        True,
        owner="DHCP asset review workflow",
    ),
    LogSpec(
        "security-onion-query",
        "Security Onion query client",
        "Investigation",
        "runtime",
        "security-onion-query.jsonl",
        "Structured relay query lifecycle and result-summary events.",
        "JSON Lines",
        "At 10 MiB; 5 numbered backups",
        "Current file plus 5 backups (about 60 MiB maximum)",
        DEFAULT_ROTATION_BACKUPS,
        True,
        owner="Security Onion query client",
    ),
    LogSpec(
        "operational-slo-history",
        "Operational SLO history",
        "Health",
        "runtime",
        "operational-slo-history.jsonl",
        "Periodic production health and service-level objective snapshots.",
        "JSON Lines",
        "Rewritten as a bounded record history",
        "Latest 4,032 samples (about 14 days at five-minute intervals)",
        0,
        True,
        owner="Operational SLO evaluator",
        maximum_size_bytes=64 * 1024 * 1024,
        retention_days=14,
    ),
    LogSpec(
        "llm-analysis",
        "LLM analysis transcript audit",
        "Investigation",
        "analysis",
        "llm-analysis-log.jsonl",
        "AI analysis execution records retained outside the general log directory.",
        "JSON Lines",
        "At 50 MiB by application-log maintenance",
        "Current file plus 10 gzip backups; archives expire after 30 days",
        ANALYSIS_ROTATION_BACKUPS,
        True,
        owner="AI analysis workers",
        path_class="analysis-audit",
        maximum_size_bytes=ANALYSIS_ROTATION_BYTES,
        compression="gzip",
        maintenance=True,
    ),
)

LAUNCHD_STEMS: Final = (
    ("launchd-ensure-stack", "Stack ensure scheduler"),
    ("launchd-monitor-stack", "Stack monitor"),
    ("harness-maintenance", "Harness maintenance"),
    ("evaluation-artifact-maintenance", "Evaluation artifact maintenance"),
    ("runtime-backup", "Runtime backup"),
    ("onion-sentinel-web-guard", "Onion Sentinel web guard"),
    ("onion-sentinel-web", "Onion Sentinel web service"),
    ("ac-hunter", "AC Hunter collector"),
    ("ai-analysis-cli", "AI analysis CLI worker"),
    ("ai-analysis", "AI analysis worker"),
    ("alert-store-maintenance", "Alert Store maintenance"),
    ("alert-store-host", "Alert Store service"),
    ("daily-rollup", "Daily rollup"),
    ("dashboard-refresh", "Dashboard refresh"),
    ("dhcp-asset-discovery", "DHCP asset discovery service"),
    ("endpoint-software-inventory", "Endpoint Software Inventory service"),
    ("pcap-analysis", "PCAP analysis worker"),
    ("pcap-retention", "PCAP retention"),
    ("software-inventory", "Software Inventory service"),
    ("application-log-maintenance", "Application log maintenance"),
)


def _launchd_specs() -> tuple[LogSpec, ...]:
    specs: list[LogSpec] = []
    for stem, label in LAUNCHD_STEMS:
        for stream, stream_label in (("out", "standard output"), ("err", "standard error")):
            specs.append(
                LogSpec(
                    f"{stem}-{stream}",
                    f"{label} — {stream_label}",
                    "Service output",
                    "runtime",
                    f"{stem}.{stream}.log",
                    f"Raw launchd {stream_label} for the {label} job.",
                    "Text",
                    "At 10 MiB by application-log maintenance",
                    "Current file plus 5 gzip backups; archives expire after 30 days",
                    DEFAULT_ROTATION_BACKUPS,
                    True,
                    False,
                    label,
                    "runtime",
                    DEFAULT_ROTATION_BYTES,
                    "gzip",
                    "Preserve current file; prune oldest gzip generation first",
                    DEFAULT_RETENTION_DAYS,
                    True,
                )
            )
    return tuple(specs)


OTHER_SPECS: Final = (
    LogSpec(
        "alert-store-sqlite-maintenance",
        "Alert Store SQLite maintenance",
        "Maintenance",
        "runtime",
        "alert-store-sqlite-maintenance.log",
        "SQLite integrity, optimization, and maintenance output.",
        "Text",
        "At 10 MiB by application-log maintenance",
        "Current file plus 5 gzip backups; archives expire after 30 days",
        DEFAULT_ROTATION_BACKUPS,
        True,
        False,
        "Alert Store SQLite maintenance",
        "runtime",
        DEFAULT_ROTATION_BYTES,
        "gzip",
        "Preserve current file; prune oldest gzip generation first",
        DEFAULT_RETENTION_DAYS,
        True,
    ),
    LogSpec(
        "ensure-stack-runs",
        "Stack ensure run logs",
        "Maintenance",
        "runtime",
        "ensure-n8n-stack-*.log",
        "One timestamped file per stack-health reconciliation run.",
        "Text",
        "A new timestamped file is created for each run",
        "Files older than 30 days are deleted by ensure-n8n-stack",
        0,
        True,
        True,
        "Stack ensure scheduler",
        "runtime",
        DEFAULT_ROTATION_BYTES,
        "none",
        "Preserve newest runs; delete oldest runs first",
        DEFAULT_RETENTION_DAYS,
        False,
    ),
)

LOG_SPECS: Final = STRUCTURED_SPECS + _launchd_specs() + OTHER_SPECS
LOG_SPECS_BY_ID: Final = {spec.id: spec for spec in LOG_SPECS}


def is_application_log_id(value: str) -> bool:
    return bool(LOG_ID_RE.fullmatch(value) and value in LOG_SPECS_BY_ID)
